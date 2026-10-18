// SPDX-License-Identifier: AGPL-3.0-only
// The seam between the console and the edition it is built as (#496). Core fills every
// slot with nothing; `src/main.tsx` provides the edition its build resolved `@edition` to, and
// every other module reads the slots here. A component rendered without a provider, as in every
// core unit test, therefore renders core, and no core module needs to know another edition exists.

import { createContext, useContext, type ComponentType } from "react";

import type { IconName } from "../shell/icons";
import type { NavigationEntry } from "../shell/navigation";
import { edition as core } from "./core";

/** What an edition may count when it happens; core counts nothing. */
export type ConsoleEvent = "account_opened" | "approval_completed";

/**
 * A server page an edition offers in the command palette, outside the console's own routes, so
 * the palette leaves the console for it rather than navigating inside it. It is offered only
 * where the session's `features` hold the link's own `feature`: core names no feature, and
 * compares the one the edition wrote.
 */
export interface EditionLink {
  readonly label: string;
  /** A root-relative path on the console's own origin, such as a server page's. */
  readonly href: `/${string}`;
  readonly icon: IconName;
  readonly feature: string;
  /** Other names people search for, as a navigation entry's `aliases` are. */
  readonly aliases?: readonly string[];
}

/** Everything an edition adds to core's pages. Each slot follows core's own content where it appears. */
export interface Edition {
  /** Entries after core's in the sidebar, the phone's tab bar, the palette and the breadcrumbs; each still passes `visible`. */
  readonly navigation: readonly NavigationEntry[];
  /**
   * Entries among the top bar's actions, after the mode and the emergency stop and before Ask,
   * so no entry pushes the stop toward the right edge where the bar runs out of room. An item
   * that carries core's `topbar-in-menu` class, as Ask does, keeps its name in an `aria-label`
   * and its words in a `btn-label`: it shows only its icon below 1280 px, and it leaves the bar
   * at 480 px and below, and below 560 px wherever a second such action is there, so the
   * edition offers it in `paletteLinks` too, which the palette and the phone's navigation sheet
   * (Menu, which opens the navigation sheet) both list.
   */
  readonly TopBarItems: ComponentType;
  /**
   * Links in the command palette's own "Actions" group, before "Go to", and in the "Actions" group
   * of the phone's navigation sheet, which Menu opens.
   */
  readonly paletteLinks: readonly EditionLink[];
  /** Cards after the data and closure requests on Workspace settings. */
  readonly WorkspacePanels: ComponentType;
  /** Definitions after the active bundle in Workspace settings' "What this tenant is". */
  readonly TenantDefinitions: ComponentType;
  /** Cards between the profile and the data requests on My account. */
  readonly AccountPanels: ComponentType;
  /** The end of the Getting started page, after its steps. */
  readonly Welcome: ComponentType;
  /** The example request's target on "Connect this agent", where core names no workstation. */
  readonly FixtureHint: ComponentType;
  /** Something countable happened. */
  readonly event: (event: ConsoleEvent) => void;
  /**
   * Whether the person reading the console can run this deployment's operator commands: core's
   * self-hosted reader can; a hosted service's cannot, so its pages show none (#678).
   */
  readonly operatorCommands: boolean;
  /**
   * Whether an administrator here can connect a monitoring source by following the console's own
   * setup dialog, so Getting started may offer watching first, below the governed path (#678).
   * False in an edition whose monitoring setup the console cannot complete yet.
   */
  readonly watchFirst: boolean;
  /**
   * The sentence after Workspace settings' readiness warning that says how approvals can reach a
   * reviewer when nothing announces them; null keeps core's, which points at the operator's
   * notification configuration (#678).
   */
  readonly ApprovalRemedy: ComponentType | null;
}

export const EditionContext = createContext<Edition>(core);

/** The slots of the edition this console was built as. */
export function useEdition(): Edition {
  return useContext(EditionContext);
}
