// SPDX-License-Identifier: AGPL-3.0-only
// The numbers of "What ExecBound did" as a description list, shared by Home's card and the
// report page (#678). Every number with an outcome is a router link to the Activity
// list it counts, from the report's start; the labels are fixed copy and render as text.

import { Link } from "@tanstack/react-router";

import type { ReportView } from "../../api/types.gen";
import { format } from "../charts/tones";
import { activityFor, COPY, observed, rows, SENTENCES, type ValueRow } from "./value";
import "./value.css";

function Count({ row, since, action }: { row: ValueRow; since: string; action?: { action: string; label: string } }) {
  const value = format(row.count);
  if (row.outcome === undefined) return <span className="value-count mono">{value}</span>;
  const sentence = action === undefined ? SENTENCES[row.outcome] : `${SENTENCES[row.outcome]}, ${action.label}`;
  return (
    <Link
      className="value-count mono"
      to="/activity"
      search={activityFor(row.outcome, since, action?.action)}
      aria-label={`${String(row.count)} ${sentence}, ${COPY.open}`}
    >
      {value}
    </Link>
  );
}

function Parts({ row, since }: { row: ValueRow; since: string }) {
  if ((row.parts?.length ?? 0) === 0 && (row.actions?.length ?? 0) === 0 && row.note === undefined) return null;
  return (
    <ul className="value-parts">
      {row.actions?.map((top) => (
        <li key={`action-${top.action}`}>
          {top.label}{" "}
          <Count row={{ ...row, count: top.count }} since={since} action={top} />
        </li>
      ))}
      {row.parts?.map((part) => (
        <li key={part.key}>
          {part.label} <Count row={part} since={since} />
        </li>
      ))}
      {row.note !== undefined ? <li>{row.note}</li> : null}
    </ul>
  );
}

/** `level` is the observe section's heading level: 3 under Home's card title, 2 on the report
 * page, where the list sits straight under the page's h1. */
export function ValueList({ report, level = 3 }: { report: ReportView; level?: 2 | 3 }) {
  const since = report.since;
  const watched = report.observed.total > 0;
  const Heading = level === 2 ? "h2" : "h3";
  return (
    <>
      <dl className="value-list">
        {rows(report).map((row) => (
          <div key={row.key}>
            <dt>{row.label}</dt>
            <dd>
              <Count row={row} since={since} />
              <Parts row={row} since={since} />
            </dd>
          </div>
        ))}
      </dl>
      {watched ? (
        <section className="value-observe" aria-labelledby="value-observe-title">
          <Heading id="value-observe-title" className="eyebrow">
            <span className="home-figure-dot dot-obs" aria-hidden="true" /> {COPY.observeTitle}
          </Heading>
          <dl className="value-list">
            {observed(report).map((row) => (
              <div key={row.key}>
                <dt>{row.label}</dt>
                <dd>
                  <Count row={row} since={since} />
                  <Parts row={row} since={since} />
                </dd>
              </div>
            ))}
          </dl>
        </section>
      ) : null}
      <p className="home-figure-note">{COPY.footer}</p>
    </>
  );
}
