// SPDX-License-Identifier: AGPL-3.0-only
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useState, type ReactNode } from "react";

import { listExecutionsOptions, readOverviewOptions } from "../api/@tanstack/react-query.gen";
import type { Bucket, Figures, OverviewView } from "../api/types.gen";
import { Sparkline, StackedBars } from "../components/charts";
import { format } from "../components/charts/tones";
import { ExecutionDrawer } from "../components/ExecutionDrawer";
import { PrincipalName } from "../components/PrincipalName";
import { RecordTable } from "../components/RecordTable";
import type { Tone } from "../components/ui/Badge";
import { Card } from "../components/ui/Card";
import { Chips } from "../components/ui/Chips";
import { EmptyState } from "../components/ui/EmptyState";
import { PageHeading } from "../components/ui/PageHeading";
import { AccountNotices } from "../components/home/AccountNotices";
import { ValueCard } from "../components/home/ValueCard";
import { NextStep } from "../components/welcome/NextStep";
import { UnroutedLine, unroutedShown, useUnrouted } from "../components/directory/UnroutedNotice";
import { recordRow, returnFocus } from "../lib/return-focus";
import { usePolledQuery } from "../lib/poll";
import { useSession } from "../lib/session";
import { bucketName, ticks } from "../lib/days";
import {
  compared,
  isRange,
  percent,
  plural,
  RANGE_WORDS,
  RANGES,
  type Range,
} from "../lib/words";
import { useServerNow } from "../lib/clock";
import { Deadline } from "../components/ui/Time";
import { useTimeZone, utcOffsetMinutes } from "../lib/time";

const RECENT = 8;
const FILTERS = [
  { value: "ALL", label: "All" },
  { value: "EXECUTED", label: "Executed" },
  { value: "DENIED", label: "Denied" },
  { value: "PENDING_APPROVAL", label: "Held" },
  { value: "OBSERVED", label: "Observed" },
] as const;
type Filter = (typeof FILTERS)[number]["value"];
/** The outcomes a legend item can draw: every figure but the headline. */
type Outcome = Exclude<keyof Figures, "decisions">;
/**
 * Which figure of a bucket a legend item draws, by the figure's own name. Keyed by field and
 * not by tone, because Held and Effect unknown share the hold tone and would otherwise share
 * one column (#678).
 */
function column(field: Outcome, bucket: Bucket): number {
  return bucket[field];
}

export interface HomeSearch {
  range?: Range;
  open?: string;
}

export const Route = createFileRoute("/")({
  validateSearch: (search: Record<string, unknown>): HomeSearch => ({
    range: isRange(search.range) ? search.range : undefined,
    open: typeof search.open === "string" && search.open !== "" ? search.open : undefined,
  }),
  component: Home,
});

/** A pending approval's deadline on Home, against the server's clock. */
function NeedsDeadline({ at }: { at: string }) {
  return <Deadline at={at} now={useServerNow()} />;
}

function Figure({
  label,
  tone,
  value,
  note,
  children,
}: {
  label: string;
  tone?: Tone;
  value: number;
  note: ReactNode;
  children?: ReactNode;
}) {
  return (
    <div className="home-figure">
      <div className="home-figure-head">
        <span className="home-figure-label">
          {tone !== undefined ? <span className={`home-figure-dot dot-${tone}`} aria-hidden="true" /> : null}
          {label}
        </span>
        {children}
      </div>
      <p className="home-figure-value">{format(value)}</p>
      <p className="home-figure-note">{note}</p>
    </div>
  );
}

function Legend({ items }: { items: { label: string; tone: Tone; field: Outcome; value: number }[] }) {
  return (
    <span className="legend">
      {items.map((item) => (
        <span key={item.label}>
          <i className={`home-figure-dot dot-${item.tone}`} aria-hidden="true" />
          {item.label} {format(item.value)}
        </span>
      ))}
    </span>
  );
}

function NeedsYou({
  data,
  approver,
  admin,
  onOpen,
}: {
  data: OverviewView;
  approver: boolean;
  admin: boolean;
  onOpen: (id: string) => void;
}) {
  // Held requests too few people can decide, for a workspace administrator alone (#678); the
  // hook makes no call for anyone else.
  const unrouted = useUnrouted().data;
  const unroutedLine = <UnroutedLine data={unrouted} />;
  const cannot = unrouted?.pending ?? 0;
  if (approver || data.awaiting.length > 0) {
    return (
      <>
        {data.awaiting.length === 0 ? (
          <EmptyState title="Nothing awaits your decision.">Approvals in your scope appear here.</EmptyState>
        ) : (
          <ul className="needs">
            {data.awaiting.map((item) => (
              <li key={item.approval_id}>
                <button
                  type="button"
                  className="row-link"
                  onClick={() => {
                    onOpen(item.execution_id);
                  }}
                >
                  <strong>{item.action_label}</strong>
                  <small>
                    <span className="mono">{item.target.provider_id}</span> · {item.target.resource_class} ·{" "}
                    <PrincipalName principal={item.agent} />
                  </small>
                </button>
                <span className="needs-meta">
                  <NeedsDeadline at={item.expires_at} />
                </span>
              </li>
            ))}
          </ul>
        )}
        {unroutedLine}
        <p>
          <Link to="/approvals">All approvals</Link>
        </p>
      </>
    );
  }
  const monitoring = data.monitoring;
  const rows: ReactNode[] = [];
  if (data.pending_approvals > 0) {
    rows.push(
      <li key="pending">
        <span>
          {cannot > 0
            ? `${plural(data.pending_approvals, "approval")} pending; ${String(cannot)} cannot be approved as things stand`
            : `${plural(data.pending_approvals, "approval")} pending with an approver`}
        </span>
        {admin ? (
          // Only an administrator can use Waiting on others, with each request's time left,
          // who can decide it and the way to assign themselves (#678).
          <Link to="/approvals" search={{ view: "others" }}>
            Open
          </Link>
        ) : (
          <Link to="/activity" search={{ state: "PENDING_APPROVAL" }}>
            Open
          </Link>
        )}
      </li>,
    );
  }
  // Before any other line about waiting: these are requests nobody can decide any more.
  if (data.lapsed_approvals > 0) {
    rows.push(
      <li key="lapsed">
        <span>{plural(data.lapsed_approvals, "approval")} lapsed before a decision</span>
        <Link to="/activity" search={{ outcome: "lapsed", state: "PENDING_APPROVAL" }}>
          Review
        </Link>
      </li>,
    );
  }
  if (data.unsettled > 0) {
    rows.push(
      <li key="unsettled">
        <span>{plural(data.unsettled, "dispatch", "dispatches")} awaiting provider evidence</span>
        <Link to="/activity" search={{ state: "UNCERTAIN" }}>
          Reconcile
        </Link>
      </li>,
    );
  }
  // Quiet is stale sources plus overdue collections, the one meaning Monitoring uses (#678).
  const quiet = monitoring === null ? 0 : monitoring.stale + monitoring.overdue;
  if (quiet > 0) {
    rows.push(
      <li key="stale">
        <span>{plural(quiet, "monitoring source or collection", "monitoring sources or collections")} quiet</span>
        <Link to="/monitor" search={{ focus: "quiet" }}>
          Open
        </Link>
      </li>,
    );
  }
  if (monitoring !== null && monitoring.open_findings > 0) {
    rows.push(
      <li key="findings">
        <span>{plural(monitoring.open_findings, "open finding")}</span>
        <Link to="/monitor" search={{ view: "findings" }}>
          Review
        </Link>
      </li>,
    );
  }
  if (rows.length === 0) {
    // A request that lapsed for want of a reviewer is not a decided approval, so while the line
    // has anything to say the empty state does not claim every approval was decided.
    if (unroutedShown(unrouted)) {
      return <EmptyState title="Nothing is waiting now.">{unroutedLine}</EmptyState>;
    }
    // A workspace no request has reached says so, rather than calling nothing settled.
    return data.last_request_at === null ? (
      <EmptyState title="Nothing yet.">No request has reached a decision.</EmptyState>
    ) : (
      <EmptyState title="Nothing is waiting.">Every decision is settled and every approval decided.</EmptyState>
    );
  }
  return (
    <>
      <ul className="needs">{rows}</ul>
      {data.pending_approvals > 0 && cannot === 0 ? (
        <p className="home-figure-note">These approvals are assigned to other people.</p>
      ) : null}
      {unroutedLine}
    </>
  );
}

function Overview({
  data,
  range,
  approver,
  admin,
  onOpen,
}: {
  data: OverviewView;
  range: Range;
  approver: boolean;
  admin: boolean;
  onOpen: (id: string) => void;
}) {
  const span = RANGE_WORDS[range];
  const step = data.step_seconds >= 86400 ? "day" : `${String(data.step_seconds / 3600)} hours`;
  const figures = data.figures;
  const previous = data.previous;
  // Every outcome the headline counts is in the legend, so the tiles, the legend and the
  // headline are one arithmetic and a percentage is taken against what the reader can see
  // (#426).
  const legend: { label: string; tone: Tone; field: Outcome; value: number }[] = [
    { label: "Executed", tone: "allow", field: "executed", value: figures.executed },
    { label: "Held", tone: "hold", field: "held", value: figures.held },
    { label: "Denied", tone: "deny", field: "denied", value: figures.denied },
    { label: "Observed", tone: "obs", field: "observed", value: figures.observed },
    { label: "Stale", tone: "stale", field: "stale", value: figures.stale },
    { label: "Effect unknown", tone: "hold", field: "unknown", value: figures.unknown },
  ];
  const counted = legend.reduce((sum, item) => sum + item.value, 0);
  return (
    <>
      <div className="home-figures">
        <Figure
          label="Decisions"
          value={figures.decisions}
          note={compared(figures.decisions, previous.decisions, span, previous.decisions)}
        >
          <Sparkline
            title={`Decisions per ${step} over the last ${span}`}
            values={data.series.map((bucket) => bucket.decisions)}
          />
        </Figure>
        <Figure label="Executed" tone="allow" value={figures.executed} note={percent(figures.executed, counted)} />
        {/* The no-baseline sentence is said once, on the headline; a share is always true. */}
        <Figure label="Denied" tone="deny" value={figures.denied} note={percent(figures.denied, counted)} />
        <Figure label="Stale" tone="stale" value={figures.stale} note={percent(figures.stale, counted)} />
        <Figure
          label="Held for a person"
          tone="hold"
          value={data.pending_approvals}
          // The server reads each deadline on its own clock (#678), so this counts only what
          // a person can still decide; a lapse is said beside it, not counted in it.
          note={
            data.lapsed_approvals > 0 ? (
              // Exactly the set the count holds: still held, and lapsed before a decision.
              <Link to="/activity" search={{ outcome: "lapsed", state: "PENDING_APPROVAL" }}>
                {`${String(data.lapsed_approvals)} lapsed before a decision · Review`}
              </Link>
            ) : approver
                ? `${plural(data.awaiting.length, "approval")} awaiting you`
                : "Waiting for a person"
          }
        />
        <Figure
          label="Unsettled"
          tone="hold"
          value={data.unsettled}
          note={
            data.unsettled > 0 ? (
              <Link to="/activity" search={{ state: "UNCERTAIN" }}>
                Awaiting provider evidence · Reconcile
              </Link>
            ) : (
              "Nothing awaits provider evidence"
            )
          }
        >
          <span className="muted">Open now</span>
        </Figure>
        <Figure
          label="Effect unknown"
          tone="hold"
          value={figures.unknown}
          note={
            figures.unknown > 0 ? (
              <Link to="/activity" search={{ state: "FAILED_EFFECT_UNKNOWN" }}>
                Review
              </Link>
            ) : (
              "No outcome with an unknown effect"
            )
          }
        >
          <span className="muted">Open now</span>
        </Figure>
      </div>
      <div className="home-grid">
        <Card title="Decisions" aside={<Legend items={legend} />}>
          <StackedBars
            title={`Decisions by outcome over the last ${span}`}
            labels={ticks(range, data.series)}
            columns={data.series.map((bucket) => bucketName(range, bucket.start))}
            span={span}
            step={step}
            series={legend.map((item) => ({
              label: item.label,
              tone: item.tone,
              values: data.series.map((bucket) => column(item.field, bucket)),
            }))}
          />
          <p className="home-figure-note">Every {step}</p>
        </Card>
        <Card
          title={approver || data.awaiting.length > 0 ? "Needs you" : "Waiting on a person"}
          aside={<span className="muted">{approver || data.awaiting.length > 0 ? plural(data.awaiting.length, "approval") : plural(data.pending_approvals, "approval")}</span>}
        >
          <NeedsYou data={data} approver={approver} admin={admin} onOpen={onOpen} />
        </Card>
      </div>
    </>
  );
}

function Home() {
  const { range = "7d", open } = Route.useSearch();
  const navigate = useNavigate({ from: "/" });
  const session = useSession();
  const [filter, setFilter] = useState<Filter>("ALL");
  const [choice] = useTimeZone();
  // The offset at the viewer's most recent midnight in the zone they chose: how the server
  // finds the day the week or the month ends with.
  const offset = String(utcOffsetMinutes(choice));
  const overview = usePolledQuery(readOverviewOptions({ query: { range, utc_offset: offset } }));
  const recent = usePolledQuery(
    listExecutionsOptions({ query: { limit: RECENT, ...(filter === "ALL" ? {} : { state: filter }) } }),
  );
  const openRecord = (id: string) => {
    void navigate({ search: (previous) => ({ ...previous, open: id }) });
  };
  const close = () => {
    void navigate({ search: (previous) => ({ ...previous, open: undefined }) });
    // The list is polled and may have drawn a new row under the drawer; land on it again.
    if (open !== undefined) returnFocus(recordRow(open));
  };
  const data = overview.data;
  const approver = session.role === "APPROVER";
  const items = recent.data?.items ?? [];
  return (
    <>
      <PageHeading
        title="Home"
        lead="What your agents asked for, and what ExecBound decided."
        actions={
          <div className="segments" role="group" aria-label="Range">
            {RANGES.map((option) => (
              <button
                key={option}
                type="button"
                className="btn"
                aria-pressed={option === range}
                onClick={() => {
                  void navigate({ search: (previous) => ({ ...previous, range: option }) });
                }}
              >
                {RANGE_WORDS[option]}
              </button>
            ))}
          </div>
        }
      />
      {overview.isError ? <p role="alert">The overview could not load.</p> : null}
      {session.role === "ADMIN" ? <NextStep /> : null}
      {session.role === "ADMIN" ? <AccountNotices /> : null}
      {data === undefined ? (
        overview.isError ? null : (
          <p role="status" className="muted">
            Loading
          </p>
        )
      ) : (
        <Overview data={data} range={range} approver={approver} admin={session.role === "ADMIN"} onOpen={openRecord} />
      )}
      {/* Under the chart and Needs you, above Recent decisions (#678). */}
      <ValueCard range={range} offset={offset} />
      <Card
        title="Recent decisions"
        aside={
          <>
            <Chips label="Show" chips={FILTERS} value={filter} onChange={setFilter} />
            <Link to="/activity">Open Activity</Link>
          </>
        }
      >
        {recent.isError ? <p role="alert">Recent decisions could not load.</p> : null}
        {recent.data !== undefined && items.length === 0 ? (
          <EmptyState title="No decisions yet.">
            {filter === "ALL" ? "Decisions appear here as agents ask." : "Nothing matches this filter."}
          </EmptyState>
        ) : null}
        {items.length > 0 ? (
          <RecordTable
            caption="Recent decisions: time, agent, action, target, decision and note"
            items={items}
            open={open}
            onOpen={openRecord}
            density="compact"
            days
          />
        ) : null}
      </Card>
      <ExecutionDrawer
        executionId={open}
        onClose={close}
        actions={(detail) => (
          <Link className="btn btn-primary" to="/activity" search={{ open: detail.execution_id }}>
            Open in Activity
          </Link>
        )}
      />
    </>
  );
}
