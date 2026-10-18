// SPDX-License-Identifier: AGPL-3.0-only
import { Link } from "@tanstack/react-router";

import type { MonitorSnapshot } from "../../api/types.gen";
import { when } from "../../lib/when";
import { Card } from "../ui/Card";
import { Table, Td, Th } from "../ui/Table";
import { STORY_ID } from "./search";

/** The External activity view: recent observations, newest first, with how each was obtained. */
export function Activity({ data }: { data: MonitorSnapshot }) {
  return (
    <Card title="Recent observations">
      <Table caption="Recent observations, newest first, with how each was obtained." density="compact">
        <thead>
          <tr>
            <Th>Occurred / received</Th>
            <Th>Story / action</Th>
            <Th>Evidence</Th>
            <Th>Outcome</Th>
            <Th>Evaluation</Th>
          </tr>
        </thead>
        <tbody>
          {data.observations.length === 0 ? (
            <tr>
              <Td colSpan={5}>No observations received. This does not establish that no external activity occurred.</Td>
            </tr>
          ) : (
            data.observations.map((item) => (
              <tr key={item.observation_id}>
                <Td mono>
                  {when(item.occurred_at)}
                  <small>Received {when(item.received_at)}</small>
                </Td>
                <Td>
                  {item.story_id !== null && STORY_ID.test(item.story_id) ? (
                    <Link to="/monitor" search={{ view: "inventory", story: item.story_id }} className="mono">
                      {item.story_id}
                    </Link>
                  ) : (
                    <span className="mono">{item.story_id ?? ""}</span>
                  )}
                  <small>{item.action ?? "Heartbeat"}</small>
                </Td>
                <Td>
                  {item.evidence === "collected" ? (
                    <>
                      Collected
                      <small>
                        {item.operation_name ?? ""} by actor {item.actor_ref ?? "unrecorded"}
                        {/* A directory's audit log names the object acted on, by id alone (#355). */}
                        {item.target_ref !== null ? ` on ${item.target_ref}` : ""}
                      </small>
                    </>
                  ) : (
                    <>
                      Reported
                      <small>{item.target_ref ?? "No target reference"}</small>
                    </>
                  )}
                </Td>
                <Td>
                  {item.outcome ?? "Not applicable"}
                  {item.action !== null ? (
                    <small>
                      {item.evidence === "collected"
                        ? "Platform-recorded; effect unverified"
                        : "Source-reported; effect unverified"}
                    </small>
                  ) : null}
                </Td>
                <Td>
                  {item.evaluation_result ?? item.evaluation_state}
                  {item.integrity_conflict_at !== null ? <small>Conflicting event identifier</small> : null}
                  {item.finding_ids[0] !== undefined ? (
                    <small>
                      <Link to="/monitor" search={{ view: "findings", state: "all", open: item.finding_ids[0] }}>
                        {item.finding_ids.length === 1 ? "Open finding" : `Open findings (${String(item.finding_ids.length)})`}
                      </Link>
                    </small>
                  ) : null}
                </Td>
              </tr>
            ))
          )}
        </tbody>
      </Table>
      <p className="muted">
        Latest {data.observations.length} observations shown. Unknown action semantics remain insufficient evidence.
        Monitoring records do not consume or refund protected execution limits.
      </p>
    </Card>
  );
}
