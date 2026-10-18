// SPDX-License-Identifier: AGPL-3.0-only
// The six monitoring views, as `/monitor/{view}` serves them today: the label the tab strip
// shows and the sentence under the heading. The order is the page's.

import type { View } from "./search";

export { VIEWS, type View } from "./search";

export const VIEW_LABELS: Record<View, string> = {
  connections: "Connections",
  inventory: "Inventory",
  agents: "Agents",
  activity: "External activity",
  findings: "Findings",
  alerts: "Alert settings",
};

export const INTRODUCTIONS: Record<View, string> = {
  connections: "See which stories report and where coverage is missing.",
  inventory:
    "See the stories, actions and credential metadata discovered in the connected platform, and which of them report.",
  agents: "See what each agent the directory lists can reach, through which path, and whether anything governs that path.",
  activity: "See reported activity while credentials stay in Tines.",
  findings: "Review what the detection rules found in reported activity, collected records and directory agents.",
  alerts: "Inspect notification delivery separately from the findings it reports.",
};
