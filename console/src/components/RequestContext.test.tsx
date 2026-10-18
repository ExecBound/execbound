// SPDX-License-Identifier: AGPL-3.0-only
import { screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { DeliveryView } from "../api/types.gen";
import { renderPage } from "../test/page";
import { DELIVERY_LABELS, RequestContext } from "./RequestContext";

function delivery(kind: DeliveryView["kind"], id: string, state = "DELIVERED"): DeliveryView {
  return {
    delivery_id: id,
    kind,
    state,
    attempts: 1,
    created_at: "2026-10-08T13:30:00+00:00",
    delivered_at: state === "DELIVERED" ? "2026-10-08T13:30:09+00:00" : null,
  };
}

describe("the request context's technical details (#678)", () => {
  it("names each delivery by its message", async () => {
    renderPage(
      <RequestContext
        externalCase={null}
        related={[]}
        executionId="44444444-0000-4000-8000-000000000001"
        approvalId="55555555-0000-4000-8000-000000000002"
        deliveries={[
          delivery("approval.pending", "66666666-0000-4000-8000-000000000001"),
          delivery("approval.reminder", "66666666-0000-4000-8000-000000000002", "PENDING"),
          delivery("approval.closed", "66666666-0000-4000-8000-000000000003"),
        ]}
      />,
    );
    const terms = (await screen.findAllByRole("term")).map((term) => term.textContent);
    expect(terms).toEqual([
      "Execution ID",
      "Approval ID",
      "Delivery · delivered · 1 attempts",
      "Reminder delivery · pending · 1 attempts",
      "Outcome delivery · delivered · 1 attempts",
    ]);
    expect(DELIVERY_LABELS).toEqual({
      "approval.pending": "Delivery",
      "approval.reminder": "Reminder delivery",
      "approval.closed": "Outcome delivery",
    });
  });
});
