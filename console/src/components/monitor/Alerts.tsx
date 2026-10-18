// SPDX-License-Identifier: AGPL-3.0-only
import { Link } from "@tanstack/react-router";

import type { MonitorDestination, MonitorSnapshot } from "../../api/types.gen";
import { useEdition } from "../../edition/context";
import { useService } from "../../lib/session";
import { count, prefix } from "../../lib/when";
import { Card } from "../ui/Card";
import { Definition, Definitions } from "../ui/Definitions";
import { Table, Td, Th } from "../ui/Table";
import "../ui/table-stack.css";

/** Said where this workspace has no findings destination (#31). */
export const NOT_SENT =
  "No findings destination is configured for this workspace, so findings are not sent outside the console. They appear under Findings, in the count beside Monitoring in the sidebar, and on Home.";

/** Said above the destinations: what is sent, once, and what it is not. */
export const SENT =
  "Each finding is sent once, within about five minutes, to every destination below that accepts its rule and its Space. A finding acknowledged before it is sent is not sent. Findings report what was seen. They never block or allow an action.";

/** A destination's rules, as the server names them. */
export function rulesWords(destination: MonitorDestination): string {
  return destination.rules === null ? "Every rule" : destination.rules.join(", ");
}

/**
 * A destination's Spaces, each part apart so a comma in a name runs into nothing: by name, in
 * name order, where the reader may read them, then the rest counted. A configured id the server
 * says is no Space of this workspace is a mistake in the configuration, said as one, never as a
 * Space the reader cannot see; only a reader of every Space is ever told of one.
 */
export function spacesWords(destination: MonitorDestination): string[] {
  if (destination.spaces === null) return ["Every Space"];
  const said = destination.spaces.map((space) => space.name).sort((a, b) => a.localeCompare(b));
  if (destination.other_spaces > 0) said.push(`${count(destination.other_spaces, "Space")} you cannot see`);
  if (destination.unknown_spaces > 0) said.push(count(destination.unknown_spaces, "unknown Space ID"));
  return said;
}

/** Whether every Space a destination names is unknown, so no finding can reach it. */
export function receivesNothing(destination: MonitorDestination): boolean {
  return destination.spaces?.length === 0 && destination.other_spaces === 0 && destination.unknown_spaces > 0;
}

/**
 * The Alert settings view (#678, #31): the findings destinations this workspace's private
 * configuration names, never an address or a secret; every delivery, with its destination, in
 * every edition; and, where the reader runs this deployment's operator commands, the local test
 * receiver, folded.
 */
export function Alerts({ data }: { data: MonitorSnapshot }) {
  const { operatorCommands } = useEdition();
  const service = useService();
  return (
    <>
      <Card title="Where findings appear">
        {data.destinations.length === 0 ? (
          // A status, as the console's other empty states are.
          <p role="status">{NOT_SENT}</p>
        ) : (
          <>
            <p>{SENT}</p>
            <Table
              caption="Findings destinations, as this deployment's private configuration names them. Addresses and secrets are never shown."
              density="compact"
              className="table-stack"
            >
              <thead>
                <tr>
                  <Th>Destination</Th>
                  <Th>Kind</Th>
                  <Th>Host</Th>
                  <Th>Rules</Th>
                  <Th>Spaces</Th>
                </tr>
              </thead>
              <tbody>
                {data.destinations.map((item) => (
                  <tr key={item.destination_id}>
                    <Td mono>{item.destination_id}</Td>
                    <Td data-label="Kind">{item.kind}</Td>
                    <Td mono={item.host !== ""} data-label="Host">
                      {item.host === "" ? "None" : item.host}
                    </Td>
                    <Td mono={item.rules !== null} data-label="Rules">
                      {rulesWords(item)}
                    </Td>
                    <Td data-label="Spaces">
                      <ul className="monitor-spaces">
                        {spacesWords(item).map((part, index) => (
                          <li key={index}>{part}</li>
                        ))}
                      </ul>
                      {receivesNothing(item) ? <p className="monitor-note monitor-spaces-none">Receives no findings</p> : null}
                    </Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          </>
        )}
        <p className="muted">
          {service.operator ?? "This deployment's operator"} sets findings destinations in its private configuration.
        </p>
      </Card>
      <Card title="Deliveries">
        <Table caption="Finding deliveries, newest first." density="compact" className="table-stack">
          <thead>
            <tr>
              <Th>Delivery</Th>
              <Th>Finding</Th>
              <Th>Destination</Th>
              <Th>State</Th>
              <Th>Attempts</Th>
              <Th>Last error</Th>
            </tr>
          </thead>
          <tbody>
            {data.deliveries.length === 0 ? (
              <tr>
                <Td colSpan={6}>No deliveries recorded.</Td>
              </tr>
            ) : (
              data.deliveries.map((item) => (
                <tr key={item.delivery_id}>
                  <Td mono>{prefix(item.delivery_id)}</Td>
                  <Td mono data-label="Finding">
                    <Link to="/monitor" search={{ view: "findings", state: "all", open: item.finding_id }}>
                      {prefix(item.finding_id)}
                    </Link>
                  </Td>
                  <Td mono={item.destination_id !== null} data-label="Destination">
                    {item.destination_id ?? "Not routed"}
                  </Td>
                  <Td data-label="State">{item.state}</Td>
                  <Td data-label="Attempts">{item.attempts}</Td>
                  <Td data-label="Last error">{item.last_error ?? "None"}</Td>
                </tr>
              ))
            )}
          </tbody>
        </Table>
        <p className="muted">
          A pending delivery is not a lost finding. One that failed with DELIVERY_UNCERTAIN may still have arrived,
          so check the destination for its delivery ID.
        </p>
      </Card>
      {operatorCommands ? (
        <details className="card monitor-receiver">
          <summary>Local test receiver</summary>
          <p className="muted">
            Where no findings destination is configured, <code>process --deliver-local</code> sends findings to an
            authenticated loopback test receiver. Its deliveries are listed above as local-receiver.
          </p>
          <Definitions aria-label="Local test receiver">
            <Definition term="Destination">The receiver the monitoring file names, listed as local-receiver</Definition>
            <Definition term="Payload">Finding, observation, source and delivery identifiers; rule version; the finding&apos;s link</Definition>
            <Definition term="Retry policy">At most five attempts; stable delivery ID and bounded backoff</Definition>
          </Definitions>
        </details>
      ) : null}
    </>
  );
}
