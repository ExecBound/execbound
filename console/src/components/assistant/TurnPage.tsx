// SPDX-License-Identifier: AGPL-3.0-only
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";

import { readAssistantTurnOptions } from "../../api/@tanstack/react-query.gen";
import { turnTitle } from "../../lib/assistant";
import { when } from "../../lib/when";
import { Card } from "../ui/Card";
import { PageHeading } from "../ui/PageHeading";
import { Turn } from "./Turn";

/**
 * One turn, its steps arriving as the server takes them (#330). A turn is the asking person's:
 * another person's id answers 404 here exactly as it does to anyone else, administrator
 * included, so there is nothing to hide in this component.
 */
export function TurnPage({ turnId }: { turnId: string }) {
  const query = useQuery({
    ...readAssistantTurnOptions({ path: { turn_id: turnId } }),
    throwOnError: (_error, failed) => failed.state.data === undefined,
  });
  const turn = query.data;
  return (
    <>
      <PageHeading
        title={turn === undefined ? "Your question" : turnTitle(turn)}
        lead={
          turn === undefined
            ? undefined
            : `Asked ${when(turn.created_at)}. What the assistant read is listed first, then its answer and the records each part rests on.`
        }
      />
      <p>
        <Link to="/ask">Back to Ask</Link>
      </p>
      {turn === undefined ? (
        <p className="muted" role="status">
          Loading your question
        </p>
      ) : (
        <Card>
          <Turn turn={turn} />
        </Card>
      )}
    </>
  );
}
