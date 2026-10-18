// SPDX-License-Identifier: AGPL-3.0-only
// Home's "What ExecBound did" card (#678): what was refused, capped, held, decided and
// lapsed over Home's range, each number one link from the list it counts. It reads the report
// once and again when the window regains focus; it never polls, so a hidden tab asks nothing.

import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";

import { readReportOptions } from "../../api/@tanstack/react-query.gen";
import type { Range } from "../../lib/words";
import { Card } from "../ui/Card";
import { Time } from "../ui/Time";
import { COPY } from "./value";
import { ValueList } from "./ValueList";

export function ValueCard({ range, offset }: { range: Range; offset: string }) {
  const report = useQuery({
    ...readReportOptions({ query: { range, utc_offset: offset } }),
    staleTime: 60_000,
  });
  const data = report.data;
  return (
    <Card
      title={COPY.title}
      className="value-card"
      aside={
        data === undefined ? undefined : (
          <>
            <span className="muted">
              {COPY.since} <Time at={data.since} /> · {data.space}
            </span>
            <Link to="/report" search={{ range }}>
              {COPY.full}
            </Link>
          </>
        )
      }
    >
      {report.isError ? <p role="alert">What ExecBound did could not load.</p> : null}
      {data === undefined ? (
        report.isError ? null : (
          <p role="status" className="muted">
            Loading
          </p>
        )
      ) : (
        <ValueList report={data} />
      )}
    </Card>
  );
}
