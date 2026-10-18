// SPDX-License-Identifier: AGPL-3.0-only
import { useQuery } from "@tanstack/react-query";
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useEffect, useRef, useState } from "react";

import { listExecutionsOptions, readExecutionOptions } from "../api/@tanstack/react-query.gen";
import type { ExecutionSummary, ListExecutionsData, ReconcileResult } from "../api/types.gen";
import { ExecutionDrawer } from "../components/ExecutionDrawer";
import { RecordTable } from "../components/RecordTable";
import { ReconcileDialog } from "../components/ReconcileDialog";
import { Card } from "../components/ui/Card";
import { Chips } from "../components/ui/Chips";
import { EmptyState } from "../components/ui/EmptyState";
import { PageHeading } from "../components/ui/PageHeading";
import { activitySearch, type ActivitySearch } from "../lib/activity-search";
import { OUTCOME_WORDS } from "../components/home/value";
import { useDensity } from "../lib/density";
import { announce } from "../lib/announce";
import { recordRow, returnFocus } from "../lib/return-focus";
import { useSession } from "../lib/session";
import { toast } from "../lib/toast";
import { shortId } from "../lib/words";
import { PrincipalName } from "../components/PrincipalName";
import { Time } from "../components/ui/Time";
import { titleNoun, titleRef, usePageName, type PageName } from "../shell/page-name";

// The list every 10 s while the tab is visible (#333); pages of fifty.
const POLL_MS = 10_000;
const PAGE = 50;
const STATE_CHIPS = [
  { value: "ALL", label: "All" },
  { value: "UNCERTAIN", label: "Uncertain" },
  { value: "PENDING_APPROVAL", label: "Held" },
  { value: "EXECUTED", label: "Executed" },
  { value: "DENIED", label: "Denied" },
  { value: "OBSERVED", label: "Observed" },
  { value: "FAILED_NOT_EXECUTED", label: "Not executed" },
  { value: "STALE_AUTHORIZATION", label: "Stale" },
] as const;
const SINCE_CHIPS = [
  { value: "ALL", label: "Any time" },
  { value: "1h", label: "Last hour" },
  { value: "24h", label: "24 hours" },
  { value: "7d", label: "7 days" },
  { value: "30d", label: "30 days" },
] as const;
const PINNED = ["outcome", "from", "action", "agent", "target"] as const;
const VERBS = { provider: "Reconcile", record: "Settle from record", correction: "Correct settlement" } as const;

type ListQuery = NonNullable<ListExecutionsData["query"]>;

/**
 * The agent filter's chip: the agent's one name, from the rows already loaded, which all belong
 * to it under the filter (#678). With none loaded it names the filter, not a principal, with the
 * id's prefix as secondary text.
 */
function AgentChip({ id, items }: { id: string; items: ExecutionSummary[] }) {
  const row = items.find((item) => item.agent.principal_id === id);
  if (row !== undefined) return <PrincipalName principal={row.agent} />;
  return (
    <>
      Agent filter <span className="mono faint">{shortId(id)}</span>
    </>
  );
}

export const Route = createFileRoute("/activity")({
  validateSearch: activitySearch,
  component: Activity,
});

/** The list's query from the URL: only the keys that are set travel. */
export function filters(search: ActivitySearch): ListQuery {
  const query: ListQuery = {};
  if (search.state !== undefined) query.state = search.state;
  if (search.outcome !== undefined) query.outcome = search.outcome;
  if (search.from !== undefined) query.from = search.from;
  if (search.action !== undefined) query.action = search.action;
  if (search.agent !== undefined) query.agent = search.agent;
  if (search.target !== undefined) query.target = search.target;
  if (search.since !== undefined) query.since = search.since;
  if (search.cursor !== undefined) query.cursor = search.cursor;
  return query;
}

/** A record open over Activity: the list it was opened from, with the same filters. */
function recordPageName(search: ActivitySearch, ref: string | undefined): PageName {
  return {
    crumbs: [{ label: "Activity", link: { to: "/activity", search } }],
    current: ref ?? "Request",
    title: [titleRef(ref) ?? titleNoun("Request")],
  };
}

/** What a changed filter set found, as the live region says it. */
function matchWords(count: number, more: boolean): string {
  if (more) return `More than ${String(PAGE)} actions match; showing the newest ${String(PAGE)}`;
  if (count === 0) return "No actions match these filters";
  return count === 1 ? "1 action matches" : `${String(count)} actions match`;
}

export function settledWords(result: ReconcileResult): string {
  return result.state === "DISPATCH_COMMITTED" || result.state === "INDETERMINATE"
    ? "Still unsettled: the provider's journal holds no terminal evidence."
    : `Settled: ${result.state_label}.`;
}

function Activity() {
  const search = Route.useSearch();
  const navigate = useNavigate({ from: "/activity" });
  const [density, toggleDensity] = useDensity();
  const [reconciling, setReconciling] = useState(false);
  const list = useQuery({ ...listExecutionsOptions({ query: filters(search) }), refetchInterval: POLL_MS });
  // The open record names the page; its drawer's own read is observed, never asked for again.
  const record = useQuery({ ...readExecutionOptions({ path: { execution_id: search.open ?? "" } }), enabled: false }).data;
  usePageName(search.open === undefined ? null : recordPageName({ ...search, open: undefined }, record?.request_ref));
  const change = (next: Partial<ActivitySearch>) => {
    void navigate({ search: (previous) => ({ ...previous, ...next }) });
  };
  const openRecord = (id: string) => {
    change({ open: id });
  };
  const close = () => {
    const was = search.open;
    setReconciling(false);
    change({ open: undefined });
    // Back to the row the record was opened from, also where it was opened from an address.
    if (was !== undefined) returnFocus(recordRow(was));
  };

  // A changed filter set is announced once its first answer arrives, never on a poll refresh
  // and never on the page's own load, which the heading already announces (#678).
  const filterKey = JSON.stringify(filters(search));
  const announced = useRef(filterKey);
  const answer = list.data;
  useEffect(() => {
    if (answer === undefined || announced.current === filterKey) return;
    announced.current = filterKey;
    announce(matchWords(answer.items.length, answer.next_cursor !== null));
  }, [filterKey, answer]);

  const items = list.data?.items ?? [];
  const uncertain = search.state === "UNCERTAIN";
  const pinned = PINNED.filter((key) => search[key] !== undefined);
  const filtered = Object.keys(filters(search)).length > 0;
  const nextCursor = list.data?.next_cursor ?? null;
  return (
    <>
      <PageHeading
        title="Activity"
        lead="Every action, accounted for."
        actions={
          <button type="button" className="btn btn-small" aria-pressed={density === "compact"} onClick={toggleDensity}>
            Compact rows
          </button>
        }
      />
      <div className="filters">
        <Chips
          label="State"
          chips={STATE_CHIPS}
          value={search.state ?? "ALL"}
          onChange={(next) => {
            change({ state: next === "ALL" ? undefined : next, cursor: undefined });
          }}
        />
        <Chips
          label="Since"
          chips={SINCE_CHIPS}
          value={search.since ?? "ALL"}
          onChange={(next) => {
            // A relative window replaces a report's start; the server takes one or the other.
            change({ since: next === "ALL" ? undefined : next, from: undefined, cursor: undefined });
          }}
        />
        {pinned.length > 0 ? (
          <div className="chips" role="group" aria-label="Pinned filters">
            {pinned.map((key) => (
              <button
                key={key}
                type="button"
                className="chip chip-on"
                aria-label={`Remove the ${key} filter`}
                onClick={() => {
                  const next: Partial<ActivitySearch> = { cursor: undefined };
                  next[key] = undefined;
                  change(next);
                }}
              >
                {key === "outcome" ? (
                  search.outcome !== undefined ? OUTCOME_WORDS[search.outcome] : ""
                ) : key === "from" ? (
                  <>
                    Since <Time at={search.from ?? ""} />
                  </>
                ) : key === "action" ? (
                  `Action ${search.action ?? ""}`
                ) : key === "agent" ? (
                  <AgentChip id={search.agent ?? ""} items={items} />
                ) : (
                  <>
                    Target <span className="mono">{shortId(search.target ?? "")}</span>
                  </>
                )}{" "}
                ×
              </button>
            ))}
          </div>
        ) : null}
      </div>
      {uncertain ? (
        <p className="muted">
          Committed or indeterminate dispatches waiting for provider evidence. An administrator settles one
          from its record, and a record without evidence stays as it is.
        </p>
      ) : null}
      <Card>
        {list.isError ? <p role="alert">Activity could not load.</p> : null}
        {list.data !== undefined && items.length === 0 ? (
          <EmptyState title="No actions to show.">
            <EmptyActivity filtered={filtered} />
          </EmptyState>
        ) : null}
        {items.length > 0 ? (
          // j and k move along the rows from anywhere on the page (#333); the row's own button
          // takes the focus, so Enter opens it as a click would.
          <div data-rows=".row-link">
            <RecordTable
              caption="Activity: time, agent, action, target, decision and note"
              items={items}
              open={search.open}
              onOpen={openRecord}
              density={density}
              extra={
                uncertain
                  ? (item) =>
                      item.reconcile.available ? (
                        <button
                          type="button"
                          className="btn btn-small"
                          onClick={(event) => {
                            event.stopPropagation();
                            openRecord(item.execution_id);
                            setReconciling(true);
                          }}
                        >
                          Reconcile
                        </button>
                      ) : null
                  : undefined
              }
            />
          </div>
        ) : null}
        <footer className="pager">
          <span className="muted">Up to {PAGE} per page, newest first</span>
          <span>
            {search.cursor !== undefined ? (
              <button
                type="button"
                className="btn btn-small"
                onClick={() => {
                  change({ cursor: undefined });
                }}
              >
                First page
              </button>
            ) : null}
            {nextCursor !== null ? (
              <button
                type="button"
                className="btn btn-small"
                onClick={() => {
                  change({ cursor: nextCursor });
                }}
              >
                Next page
              </button>
            ) : null}
          </span>
        </footer>
      </Card>
      <ExecutionDrawer
        executionId={search.open}
        onClose={close}
        actions={(detail) =>
          // The record's own Explain is below it, where the deployment has an assistant.
          detail.reconcile.available ? (
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => {
                setReconciling(true);
              }}
            >
              {VERBS[detail.reconcile.kind ?? "provider"]}
            </button>
          ) : null
        }
        after={(detail) =>
          reconciling && detail.reconcile.available ? (
            <ReconcileDialog
              detail={detail}
              onClose={() => {
                setReconciling(false);
              }}
              onSettled={(result) => {
                setReconciling(false);
                toast(settledWords(result));
              }}
            />
          ) : null
        }
      />
    </>
  );
}

/** What an empty list says (#678): a filtered one that nothing matches; an unfiltered one, by
 * role, that nothing has arrived yet and what to do about it. */
function EmptyActivity({ filtered }: { filtered: boolean }) {
  const { role } = useSession();
  if (filtered) return <>No actions match these filters.</>;
  if (role === "ADMIN") {
    return (
      <>
        No agent has sent a request in this view yet.{" "}
        <Link to="/welcome" search={{ step: "connect" }}>
          Open guided setup
        </Link>
      </>
    );
  }
  if (role === "APPROVER") return <>Requests in your review scope appear here.</>;
  return <>Actions in your scope appear here.</>;
}
