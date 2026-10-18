// SPDX-License-Identifier: AGPL-3.0-only
// Rules files in the console (#678): download a policy's rules as the file
// ruleset-compile reads, and start a draft from one, worded from the person's own file.
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { RulesFileView } from "../../api/types.gen";
import {
  ACTIVE,
  detail,
  DRAFT,
  expectNoRequests,
  json,
  mount,
  resetClient,
  stub,
} from "../../test/policy";
import { BundleDetailView } from "./BundleDetail";
import { NewDraft } from "./BundleList";
import { rulesFileNote } from "./RulesFile";

beforeEach(expectNoRequests);
afterEach(() => {
  resetClient();
  vi.restoreAllMocks();
});

const VIEW: RulesFileView = {
  filename: "execbound-rules-22222222.json",
  ruleset: { version: 1, rules: [{ id: "allow-isolation", action: "endpoint.isolate", effect: "ALLOW" }], budgets: [] },
  omitted_budgets: ["b-ops", "b-tier0"],
  omitted_context: true,
};
const SUMMARY = { available: true, omitted_budgets: ["b-ops", "b-tier0"], omitted_context: true };
const rules = () =>
  detail({
    bundle_id: DRAFT,
    content_hash: "d".repeat(64),
    state: "VALIDATED",
    active: false,
    written_as_rules: true,
    rules_origin: "rules",
    rules_file: SUMMARY,
  });

describe("download rules", () => {
  it("fetches the file once on click and hands the browser exactly its text", async () => {
    const asked = vi.fn();
    stub((request) => {
      asked(new URL(request.url).pathname);
      return Promise.resolve(json(VIEW));
    });
    const blobs: Blob[] = [];
    const create = vi.fn((blob: Blob) => {
      blobs.push(blob);
      return "blob:rules";
    });
    const revoke = vi.fn();
    vi.stubGlobal("URL", Object.assign(URL, { createObjectURL: create, revokeObjectURL: revoke }));
    const clicked: { href: string; download: string }[] = [];
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) {
      clicked.push({ href: this.getAttribute("href") ?? "", download: this.download });
    });
    mount(<BundleDetailView detail={rules()} active={{ bundle_id: ACTIVE }} />, `/policy/${DRAFT}`);
    await userEvent.click(await screen.findByRole("button", { name: "Download rules" }));
    await waitFor(() => {
      expect(revoke).toHaveBeenCalledWith("blob:rules");
    });
    expect(asked).toHaveBeenCalledTimes(1);
    expect(asked).toHaveBeenCalledWith(`/api/console/v1/policy/${DRAFT}/ruleset`);
    expect(blobs).toHaveLength(1);
    expect(blobs[0]?.type).toBe("application/json");
    expect(await blobs[0]?.text()).toBe(`${JSON.stringify(VIEW.ruleset, null, 2)}\n`);
    expect(clicked).toEqual([{ href: "blob:rules", download: "execbound-rules-22222222.json" }]);
  });

  it("says what the file leaves out before the click", async () => {
    mount(<BundleDetailView detail={rules()} active={{ bundle_id: ACTIVE }} />, `/policy/${DRAFT}`);
    expect(
      await screen.findByText(
        "The file leaves out 2 budgets counted for a named group, account or Space (b-ops, b-tier0) and this policy's context settings, because those name this workspace's own records. Rule notes and condition values are included as written.",
      ),
    ).toBeInTheDocument();
    expect(rulesFileNote({ available: true, omitted_budgets: [], omitted_context: false })).toBe(
      "Rule notes and condition values are included as written.",
    );
  });

  it("offers no download for a policy in Cedar or a recognized seed", async () => {
    const none = { available: false, omitted_budgets: [], omitted_context: false };
    mount(
      <BundleDetailView detail={detail({ rules_origin: "cedar", written_as_rules: false, rules_file: none })} active={{ bundle_id: ACTIVE }} />,
      `/policy/${ACTIVE}`,
    );
    expect(await screen.findByText(/Written in Cedar, so it cannot be downloaded as rules/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Download rules" })).toBeNull();
  });

  it("asks for an editable draft before a recognized seed's rules download", async () => {
    const none = { available: false, omitted_budgets: [], omitted_context: false };
    mount(
      <BundleDetailView detail={detail({ rules_origin: "recognized-seed", rules_file: none })} active={{ bundle_id: ACTIVE }} />,
      `/policy/${ACTIVE}`,
    );
    expect(await screen.findByText("Create an editable draft first to download its rules.")).toBeInTheDocument();
  });
});

const FILE = JSON.stringify({
  rules: [
    { id: "deny-dc", action: "endpoint.lift_isolation", effect: "DENY" },
    { id: "allow-isolation", action: "endpoint.isolate", effect: "ALLOW" },
  ],
});

function chooseFile() {
  return screen.findByLabelText("Rules file (JSON, at most 512 KB)");
}

describe("a draft from a rules file", () => {
  it("sends the file's text and opens the new draft", async () => {
    const bodies: unknown[] = [];
    stub(async (request) => {
      bodies.push(await request.clone().json());
      return json(detail({ bundle_id: DRAFT, state: "DRAFT", active: false }));
    });
    const router = mount(<NewDraft hasActive />);
    await userEvent.upload(await chooseFile(), new File([FILE], "rules.json", { type: "application/json" }));
    const create = screen.getByRole("button", { name: "Create draft from file" });
    await waitFor(() => {
      expect(create).toBeEnabled();
    });
    await userEvent.click(create);
    await waitFor(() => {
      expect(router.state.location.pathname).toBe(`/policy/${DRAFT}`);
    });
    expect(bodies).toEqual([{ source: "ruleset", ruleset: FILE }]);
  });

  it("refuses a file over 512 KB before reading or sending it", async () => {
    const read = vi.fn();
    stub(() => {
      read();
      return Promise.resolve(json({}));
    });
    mount(<NewDraft hasActive />);
    const large = new File(["x".repeat(512 * 1024 + 1)], "rules.json", { type: "application/json" });
    const text = vi.spyOn(large, "text");
    await userEvent.upload(await chooseFile(), large);
    expect(await screen.findByText("The file is larger than 512 KB.")).toBeInTheDocument();
    expect(text).not.toHaveBeenCalled();
    expect(screen.getByRole("button", { name: "Create draft from file" })).toBeDisabled();
    expect(read).not.toHaveBeenCalled();
  });

  it.each([
    [
      "INVALID_BODY",
      "This Space has no action mapping for endpoint.isolate (rule 2). Remove those rules or ask your operator to add the mapping.",
    ],
    [
      "SIGNAL_MAPPING_ONLY",
      "endpoint.isolate (rule 2) is served in this Space only by a signal mapping, which a rules file cannot carry. Paste the complete bundle under Advanced instead, or ask your operator.",
    ],
    [
      "MAPPINGS_CONFLICT",
      "Two mappings serve endpoint.isolate (rule 2) and cannot share one policy. Ask your operator to choose one with ruleset-compile --ref, then paste the bundle it prints.",
    ],
  ])("words a %s refusal from the person's own file", async (code, sentence) => {
    stub(() => Promise.resolve(json({ code, detail: "x", fields: ["ruleset.rules.1.action"] }, 400)));
    mount(<NewDraft hasActive />);
    await userEvent.upload(await chooseFile(), new File([FILE], "rules.json", { type: "application/json" }));
    const create = screen.getByRole("button", { name: "Create draft from file" });
    await waitFor(() => {
      expect(create).toBeEnabled();
    });
    await userEvent.click(create);
    expect(await screen.findByText(sentence)).toBeInTheDocument();
  });

  it("keeps nothing in the browser's storage", async () => {
    const setItem = vi.spyOn(Storage.prototype, "setItem");
    stub(() => Promise.resolve(json(detail({ bundle_id: DRAFT, state: "DRAFT", active: false }))));
    const router = mount(<NewDraft hasActive />);
    await userEvent.upload(await chooseFile(), new File([FILE], "rules.json", { type: "application/json" }));
    const create = screen.getByRole("button", { name: "Create draft from file" });
    await waitFor(() => {
      expect(create).toBeEnabled();
    });
    await userEvent.click(create);
    await waitFor(() => {
      expect(router.state.location.pathname).toBe(`/policy/${DRAFT}`);
    });
    expect(setItem).not.toHaveBeenCalled();
  });
});
