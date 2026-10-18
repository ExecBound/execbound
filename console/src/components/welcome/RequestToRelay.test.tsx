// SPDX-License-Identifier: AGPL-3.0-only
import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { RequestToRelay } from "./RequestToRelay";

// Every module of guided setup and the connection card, read as text; tests excluded.
const SOURCES = import.meta.glob<string>(["./*.ts", "./*.tsx", "!./*.test.ts", "!./*.test.tsx"], {
  query: "?raw",
  import: "default",
  eager: true,
});
const INCIDENT = "11111111-0000-4000-8000-000000000001";

/** The text of each element of `tag` in `container`, in order. */
function texts(container: HTMLElement, tag: string): (string | null)[] {
  return [...container.querySelectorAll(tag)].map((element) => element.textContent);
}

describe("the request a person relays to their agent (#545)", () => {
  it("names the operation the server gave, the target by its selector and the incident by its field", () => {
    const { container } = render(<p><RequestToRelay operationRef="op.from-the-server" kind="hostname" value="host-01.sample.invalid" incident={INCIDENT} /></p>);
    expect(container).toHaveTextContent(`call execute with operation_ref op.from-the-server, target hostname host-01.sample.invalid and claimed_context.incident_id ${INCIDENT}`);
    // Every name the agent spells is code; the target a person picked is emphasised, as the fallback has it.
    expect(texts(container, "code")).toEqual(["execute", "operation_ref", "op.from-the-server", "hostname", "claimed_context.incident_id", INCIDENT]);
    expect(texts(container, "strong")).toEqual(["host-01.sample.invalid"]);
  });

  it("names the target and its incident alone while no operation has arrived", () => {
    const { container } = render(<p><RequestToRelay operationRef={null} kind="hostname" value="host-01.sample.invalid" incident={INCIDENT} /></p>);
    expect(container).toHaveTextContent(`isolate host-01.sample.invalid for incident ${INCIDENT}`);
    expect(container).not.toHaveTextContent("operation_ref");
    expect(container).not.toHaveTextContent("claimed_context");
  });

  it("leaves out an incident the target has none of", () => {
    const { container } = render(<p><RequestToRelay operationRef="op.from-the-server" kind="provider_id" value="workstation-01" incident={null} /></p>);
    expect(container).toHaveTextContent(/^call execute with operation_ref op\.from-the-server, target provider_id workstation-01$/);
  });

  it("never spells endpoint.isolate in a welcome module", () => {
    expect(Object.keys(SOURCES)).toEqual(expect.arrayContaining(["./RequestToRelay.tsx", "./ExampleRequest.tsx", "./AgentConnection.tsx", "./WelcomePage.tsx"]));
    for (const [path, text] of Object.entries(SOURCES)) expect(text, path).not.toContain("endpoint.isolate");
  });
});
