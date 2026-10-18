// SPDX-License-Identifier: AGPL-3.0-only
import { useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";

import { listSpacesOptions } from "../../api/@tanstack/react-query.gen";
import { useSession } from "../../lib/session";
import { explain } from "../directory/errors";
import { Badge } from "../ui/Badge";
import { Button } from "../ui/Button";
import { Card } from "../ui/Card";
import { Chips } from "../ui/Chips";
import { EmptyState } from "../ui/EmptyState";
import { Field } from "../directory/forms";
import { Table, Td, Th } from "../ui/Table";
import { state } from "./words";

import { STATES, QUERY_MAX, type SpacesSearch } from "./spaces-search";
export { DEFAULT_SPACES_SEARCH, parseSpacesSearch, type SpacesSearch, type SpacesState } from "./spaces-search";

const SETTLE_MS = 150;

/**
 * The tenant's spaces, filtered by the server. A row opens its own detail beside the list
 * (`?open=`), which is the console's rule for a list with a detail; **no parameter anywhere
 * names the session's space**, so editing this URL cannot ask for another space's
 * rows — it only says which row of the person's own visible set is expanded.
 */
export function SpacesList({
  search,
  onSearch,
}: {
  search: SpacesSearch;
  onSearch: (next: Partial<SpacesSearch>) => void;
}) {
  const session = useSession();
  const [typed, setTyped] = useState(search.q);
  useEffect(() => {
    const timer = setTimeout(() => {
      if (typed.trim() !== search.q) onSearch({ q: typed.trim() });
    }, SETTLE_MS);
    return () => {
      clearTimeout(timer);
    };
  }, [typed, search.q, onSearch]);
  const query = useQuery({
    ...listSpacesOptions({
      query: { state: search.state, ...(search.q === "" ? {} : { q: search.q }) },
    }),
    refetchInterval: 30_000,
  });
  if (query.error !== null) {
    return <EmptyState title="The spaces could not be read.">{explain(query.error)}</EmptyState>;
  }
  if (query.data === undefined) return <p role="status">Loading the spaces.</p>;
  const rows = query.data.items;
  return (
    <div className="stack">
      <div className="filters">
        <Chips
          label="Which spaces"
          chips={STATES}
          value={search.state}
          onChange={(next) => {
            onSearch({ state: next });
          }}
        />
        <Field label="Filter by name" className="field-inline">
          <input
            type="text"
            value={typed}
            maxLength={QUERY_MAX}
            onChange={(event) => {
              setTyped(event.target.value);
            }}
          />
        </Field>
      </div>
      <Card>
        <Table caption="The spaces of this tenant, with their state and what each one holds." density="compact">
          <thead>
            <tr>
              <Th>Space</Th>
              <Th>State</Th>
              <Th>Members</Th>
              <Th>Agents</Th>
              <Th>Waiting</Th>
              <Th>Findings</Th>
              <Th>Open</Th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.space_id} aria-current={row.space_id === search.open ? "true" : undefined}>
                <Td>
                  <span className="space-row">
                    <strong>{row.name}</strong>
                    {row.detail !== null ? <small>{row.detail}</small> : null}
                  </span>
                </Td>
                <Td>
                  <Badge tone={row.archived_at === null ? "allow" : "stale"}>
                    {state(row.archived_at)}
                  </Badge>
                </Td>
                <Td>{row.members}</Td>
                <Td>{row.agents}</Td>
                <Td>{row.pending}</Td>
                <Td>{row.findings}</Td>
                <Td>
                  <Button
                    size="small"
                    aria-label={`Open ${row.name}`}
                    onClick={() => {
                      onSearch({ open: row.space_id });
                    }}
                  >
                    Open
                  </Button>
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
        {rows.length === 0 ? (
          <EmptyState title="No space matches.">
            {session.role === "ADMIN"
              ? "Create one from the switcher at the top of the sidebar."
              : "You belong to no space that matches this filter."}
          </EmptyState>
        ) : null}
        {query.data.next_cursor !== null ? (
          <p className="muted">
            The first fifty are shown. Narrow the filter to reach the rest.
          </p>
        ) : null}
      </Card>
    </div>
  );
}
