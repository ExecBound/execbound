// SPDX-License-Identifier: AGPL-3.0-only
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { expect, it } from "vitest";
import type { AccessGrant, AccessPage } from "../../api/types.gen";
import { GrantPicker } from "./AccessManagement";

const data: AccessPage = {
  users: [], groups: [], spaces: [{ space_id: "space-a", name: "Production" }],
  roles: [
    { id: "administrator", name: "Administrator", description: "Manage workspace", permissions: [], scopes: ["WORKSPACE"] },
    { id: "viewer", name: "Viewer", description: "Read activity", permissions: [], scopes: ["WORKSPACE", "SPACE"] },
  ],
};

it("makes a Space role workspace-wide when changed to Administrator", async () => {
  function Form() {
    const [grants, set] = useState<AccessGrant[]>([{ role: "viewer", space_id: "space-a" }]);
    return <><GrantPicker data={data} grants={grants} onChange={set} /><output>{JSON.stringify(grants)}</output></>;
  }
  render(<Form />);
  await userEvent.selectOptions(screen.getByLabelText("Role 1"), "administrator");
  expect(screen.getByLabelText("Scope 1")).toBeDisabled();
  expect(screen.getByRole("status")).toHaveTextContent('"space_id":null');
  expect(screen.getByText(/Administrator applies to the whole workspace/)).toBeInTheDocument();
});

it("keeps removal explicit instead of inserting a fallback role", async () => {
  function Form() {
    const [grants, set] = useState<AccessGrant[]>([{ role: "viewer", space_id: null }]);
    return <GrantPicker data={data} grants={grants} onChange={set} />;
  }
  render(<Form />);
  await userEvent.click(screen.getByRole("button", { name: "Remove role 1" }));
  expect(screen.getByText(/No direct roles/)).toBeInTheDocument();
});
