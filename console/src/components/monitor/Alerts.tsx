// SPDX-License-Identifier: AGPL-3.0-only
import { Link } from "@tanstack/react-router";

import type { MonitorSnapshot } from "../../api/types.gen";
import { useEdition } from "../../edition/context";
import { prefix } from "../../lib/when";
import { Card } from "../ui/Card";
import { Definition, Definitions } from "../ui/Definitions";
import { Table, Td, Th } from "../ui/Table";

/**
 * The Alert settings view (#678): where findings appear today, and, where the reader runs this
 * deployment's operator commands, the local test receiver and every delivery intent, collapsed.
 * Findings delivery to people's channels is planned work (#179).
 */
export function Alerts({ data }: { data: MonitorSnapshot }) {
  const { operatorCommands } = useEdition();
  return (
    <>
      <Card title="Where findings appear">
        <p>
          Findings are not sent outside the console in this release. They appear under Findings, in the count beside
          Monitoring in the sidebar, and on Home. Email, Slack and Teams carry approval notifications only.
        </p>
      </Card>
      {operatorCommands ? (
        <details className="card monitor-receiver">
          <summary>Local test receiver</summary>
          <p className="muted">
            Findings are retained independently of notification delivery. The explicit worker can send them to an
            authenticated loopback test receiver.
          </p>
          <Definitions aria-label="Local test receiver">
            <Definition term="Destination">Selected by the operator when running the local worker</Definition>
            <Definition term="Payload">Finding, observation, source and delivery identifiers; rule version</Definition>
            <Definition term="Retry policy">At most five attempts; stable delivery ID and bounded backoff</Definition>
          </Definitions>
          <p className="muted">
            No receiver runs automatically. Pending delivery does not mean the finding was lost. A terminal uncertain
            delivery may have reached the receiver; inspect the receiver&apos;s delivery ID.
          </p>
          <Table caption="Notification delivery intents, newest first." density="compact">
            <thead>
              <tr>
                <Th>Delivery</Th>
                <Th>Finding</Th>
                <Th>State</Th>
                <Th>Attempts</Th>
                <Th>Last error</Th>
              </tr>
            </thead>
            <tbody>
              {data.deliveries.length === 0 ? (
                <tr>
                  <Td colSpan={5}>No notification intents recorded.</Td>
                </tr>
              ) : (
                data.deliveries.map((item) => (
                  <tr key={item.delivery_id}>
                    <Td mono>{prefix(item.delivery_id)}</Td>
                    <Td mono>
                      <Link to="/monitor" search={{ view: "findings", state: "all", open: item.finding_id }}>
                        {prefix(item.finding_id)}
                      </Link>
                    </Td>
                    <Td>{item.state}</Td>
                    <Td>{item.attempts}</Td>
                    <Td>{item.last_error ?? "None"}</Td>
                  </tr>
                ))
              )}
            </tbody>
          </Table>
        </details>
      ) : null}
    </>
  );
}
