// SPDX-License-Identifier: AGPL-3.0-only
// The printable report (#678): what ExecBound recorded for requests made in the range,
// in the reader's scope, with a Print button and the same read as a CSV. It is reached from
// Home's card; it is not a navigation entry.

import { useQuery } from "@tanstack/react-query";
import { createFileRoute, useNavigate } from "@tanstack/react-router";

import { readReportOptions } from "../api/@tanstack/react-query.gen";
import { COPY } from "../components/home/value";
import { ValueList } from "../components/home/ValueList";
import { Card } from "../components/ui/Card";
import { PageHeading } from "../components/ui/PageHeading";
import { titleNoun, usePageName, type PageName } from "../shell/page-name";
import { useTimeZone, utcOffsetMinutes } from "../lib/time";
import { workspaceGeneration } from "../lib/workspace-context";
import { isRange, RANGE_WORDS, RANGES, type Range } from "../lib/words";

const CSV = "/api/console/v1/report.csv";

export interface ReportSearch {
  range?: Range;
}

/** The page names itself, since it is not a navigation entry: the crumb and the tab say what it
 * is rather than "Console" (#678). */
const REPORT_PAGE: PageName = {
  crumbs: [],
  current: COPY.title,
  title: [],
  section: titleNoun("What ExecBound did"),
};

export const Route = createFileRoute("/report")({
  // Every key named, so a value it drops is dropped rather than passed through as it came.
  validateSearch: (search: Record<string, unknown>): ReportSearch => ({
    range: isRange(search.range) ? search.range : undefined,
  }),
  component: ReportPage,
});

/** The CSV's address: the fixed path, the validated range, the viewer's offset and the session
 * generation, built as the board stream's is. No data string reaches it. */
export function csvUrl(range: Range, offset: number, generation: string): string {
  const query = new URLSearchParams();
  query.set("range", range);
  query.set("utc_offset", String(offset));
  if (generation !== "") query.set("generation", generation);
  return `${CSV}?${query.toString()}`;
}

function ReportPage() {
  usePageName(REPORT_PAGE);
  const { range = "7d" } = Route.useSearch();
  const navigate = useNavigate({ from: "/report" });
  const [choice] = useTimeZone();
  const offset = utcOffsetMinutes(choice);
  const report = useQuery({
    ...readReportOptions({ query: { range, utc_offset: String(offset) } }),
    staleTime: 60_000,
  });
  const data = report.data;
  const where = data === undefined ? "" : data.space === "All spaces" ? " in all spaces" : ` in ${data.space}`;
  return (
    <>
      <PageHeading
        title={COPY.title}
        lead={`Requests made in the last ${RANGE_WORDS[range]}${where}, as ExecBound recorded them.`}
        actions={
          <div className="page-actions">
            <div className="segments" role="group" aria-label="Range">
              {RANGES.map((option) => (
                <button
                  key={option}
                  type="button"
                  className="btn"
                  aria-pressed={option === range}
                  onClick={() => {
                    void navigate({ search: { range: option } });
                  }}
                >
                  {RANGE_WORDS[option]}
                </button>
              ))}
            </div>
            <button
              type="button"
              className="btn"
              onClick={() => {
                window.print();
              }}
            >
              Print
            </button>
            <a className="btn" href={csvUrl(range, offset, workspaceGeneration())} download>
              Download CSV
            </a>
          </div>
        }
      />
      <Card>
        {report.isError ? <p role="alert">The report could not load.</p> : null}
        {data === undefined ? (
          report.isError ? null : (
            <p role="status" className="muted">
              Loading
            </p>
          )
        ) : (
          <ValueList report={data} level={2} />
        )}
      </Card>
    </>
  );
}
