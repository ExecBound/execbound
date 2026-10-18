// SPDX-License-Identifier: AGPL-3.0-only
import type { TenantSettingsView } from "../../api/types.gen";
import { Table, Td, Th } from "../ui/Table";
import { announces, deliveryWords, messageWords } from "./delivery";
import "../ui/table-stack.css";

/**
 * Where this workspace's approvals are announced (#678): each configured destination by id, kind
 * and host, never its address or secret, with the messages it receives, then how fast
 * notifications arrived over the last week. Destinations are operator configuration, so nothing
 * here changes one.
 */
export function Announcements({ view }: { view: TenantSettingsView }) {
  return (
    <>
      <h3 className="card-subtitle">Where approvals are announced</h3>
      {/* A sentence, not a table row, so it wraps inside the card; where destinations exist, the
          table stacks each one inside a narrow card rather than running past its edge (#678). */}
      {view.destinations.length === 0 ? (
        <p className="muted">No destinations configured. Pending approvals are announced nowhere but this console.</p>
      ) : (
        <Table
          caption="Configured notification destinations, as the private configuration names them; addresses and secrets are never shown."
          density="compact"
          className="table-stack"
        >
          <thead>
            <tr>
              <Th>Destination</Th>
              <Th>Kind</Th>
              <Th>Host</Th>
              <Th>Approvers</Th>
              <Th>Messages</Th>
            </tr>
          </thead>
          <tbody>
            {view.destinations.map((item) => (
              <tr key={item.destination_id}>
                <Td mono>{item.destination_id}</Td>
                <Td data-label="Kind">{item.kind}</Td>
                <Td mono data-label="Host">{item.host}</Td>
                <Td data-label="Approvers">{item.approvers === null ? "every approver" : String(item.approvers)}</Td>
                <Td data-label="Messages">{messageWords(item)}</Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
      <DeliveryLine view={view} />
      <p className="muted">
        Destinations are operator configuration; the command line and the private configuration file change them.
      </p>
    </>
  );
}

/** How fast this workspace's notifications arrived over the last week; nothing without a destination. */
function DeliveryLine({ view }: { view: TenantSettingsView }) {
  const words = deliveryWords(view.delivery, announces(view.destinations));
  return words === null ? null : <p className="muted">{words}</p>;
}
