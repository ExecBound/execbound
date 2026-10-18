// SPDX-License-Identifier: AGPL-3.0-only
import { useQuery } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";

import { readPolicyRulesOptions } from "../api/@tanstack/react-query.gen";
import { explain } from "../components/directory/errors";
import { RulesEditor } from "../components/policy/RulesEditor";
import { EmptyState } from "../components/ui/EmptyState";
import { PageHeading } from "../components/ui/PageHeading";
import { policyName } from "../components/policy/format";
import { titleNoun, titleShort, usePageName, type PageName } from "../shell/page-name";

/** A rule id as the bundle writes one (`RuleId`); anything else is dropped. */
const RULE = /^[a-z][a-z0-9_.-]{0,79}$/;

export interface RulesSearch {
  rule?: string;
}

export const Route = createFileRoute("/policy_/$bundleId_/rules")({
  // The key named either way, so a value that fails the pattern is dropped, never passed on.
  validateSearch: (search: Record<string, unknown>): RulesSearch => ({
    rule: typeof search.rule === "string" && RULE.test(search.rule) ? search.rule : undefined,
  }),
  component: RulesRoute,
});

function rulesPageName(bundleId: string): PageName {
  const short = titleShort("Policy version", bundleId);
  return {
    crumbs: [
      { label: "Policies", link: { to: "/policy" } },
      { label: policyName(bundleId), link: { to: "/policy/$bundleId", params: { bundleId } } },
    ],
    current: "Rules",
    title: short === undefined ? [titleNoun("Rules")] : [titleNoun("Rules"), short],
  };
}

function RulesRoute() {
  const { bundleId } = Route.useParams();
  const { rule } = Route.useSearch();
  usePageName(rulesPageName(bundleId));
  const query = useQuery(readPolicyRulesOptions({ path: { bundle_id: bundleId } }));
  if (query.data !== undefined) return <RulesEditor view={query.data} focus={rule} />;
  return (
    <>
      <PageHeading title="Rules" />
      {query.error !== null ? (
        <EmptyState title="These rules could not be read.">{explain(query.error)}</EmptyState>
      ) : (
        <p role="status">Loading the rules.</p>
      )}
    </>
  );
}
