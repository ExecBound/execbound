// SPDX-License-Identifier: AGPL-3.0-only
import { createFileRoute } from "@tanstack/react-router";

import { TurnPage } from "../components/assistant/TurnPage";
import { titleNoun, usePageName, type PageName } from "../shell/page-name";

/** An assistant's answer, under Ask. */
const ANSWER_PAGE: PageName = {
  crumbs: [{ label: "Ask", link: { to: "/ask" } }],
  current: "Answer",
  title: [titleNoun("Answer")],
};

export const Route = createFileRoute("/ask_/$turnId")({
  component: TurnRoute,
});

function TurnRoute() {
  const { turnId } = Route.useParams();
  usePageName(ANSWER_PAGE);
  return <TurnPage turnId={turnId} />;
}
