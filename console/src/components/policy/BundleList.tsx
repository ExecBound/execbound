// SPDX-License-Identifier: AGPL-3.0-only
import { useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import { useEffect } from "react";

import { createPolicyBundleMutation } from "../../api/@tanstack/react-query.gen";
import type { PolicyPage } from "../../api/types.gen";
import { usePolicyDraft } from "../../lib/drafts";
import { useServerMutation } from "../../lib/mutation";
import { inAllSpaces, useSession } from "../../lib/session";
import { toast } from "../../lib/toast";
import { when } from "../directory/format";
import { Field, Problem } from "../directory/forms";
import { Badge } from "../ui/Badge";
import { Button } from "../ui/Button";
import { Card } from "../ui/Card";
import { EmptyState } from "../ui/EmptyState";
import { Table, Td, Th } from "../ui/Table";
import { policyName, retiredToggle, STATE, stateWord } from "./format";
import { RulesFileDraft } from "./RulesFile";
import "./policy.css";

type Row = PolicyPage["bundles"][number];

function newestFirst(left: Row, right: Row): number {
  return Date.parse(right.changed_at) - Date.parse(left.changed_at);
}

/**
 * The list's two parts, split on the client from the server's one list: current versions
 * first (the active selection, then drafts and validated versions newest change first, then
 * versions active in another Space), and the retired ones, newest change first.
 */
export function currentFirst(rows: readonly Row[]): { current: Row[]; retired: Row[] } {
  const selected = rows.filter((row) => row.active);
  const working = rows.filter((row) => row.state === "DRAFT" || row.state === "VALIDATED").sort(newestFirst);
  const elsewhere = rows.filter((row) => row.state === "ACTIVE" && !row.active).sort(newestFirst);
  const retired = rows.filter((row) => row.state === "RETIRED").sort(newestFirst);
  return { current: [...selected, ...working, ...elsewhere], retired };
}

function BundleRows({ rows }: { rows: readonly Row[] }) {
  const allSpaces = inAllSpaces(useSession());
  return (
    <>
      {rows.map((row) => {
        const state = STATE[row.state];
        return (
          <tr key={row.bundle_id} className={row.active ? "row-selected" : undefined}>
            <th scope="row">
              <Link to="/policy/$bundleId" params={{ bundleId: row.bundle_id }}>
                {policyName(row.bundle_id)}
              </Link>
            </th>
            <Td>
              <span className="badges">
                <Badge tone={state.tone}>{stateWord(row.state, row.active, allSpaces)}</Badge>
                {row.active ? <span className="faint">the active selection</span> : null}
                {row.sample === true ? <Badge tone="accent">Sample</Badge> : null}
              </span>
            </Td>
            <Td>{row.state === "DRAFT" ? "Edit and validate" : row.state === "VALIDATED" ? "Preview, then activate" : row.state === "ACTIVE" ? row.active ? "Create a draft to make changes" : allSpaces ? "Copy it, or choose a Space to activate it there" : "Activate for this Space or copy" : "View history"}</Td>
            <Td>
              {when(row.changed_at)}
              {/* The latest activation's reason: a person's text, clamped by the style sheet and
                  never cut, so the whole of it stays the cell's text. */}
              {row.note ? <span className="policy-note">{row.note}</span> : null}
            </Td>
          </tr>
        );
      })}
    </>
  );
}

function Head() {
  return (
    <thead>
      <tr>
        <Th>Policy version</Th>
        <Th>State</Th>
        <Th>Next step</Th>
        <Th>Changed</Th>
      </tr>
    </thead>
  );
}

/** Policy versions owned by or offered to the current Space: current ones first, with the
 *  active selection marked, and retired ones counted and folded behind a button whose state
 *  is the address (`?retired=1`), so Back and a shared link keep it. */
export function BundleList({ page, showRetired = false }: { page: PolicyPage; showRetired?: boolean }) {
  const navigate = useNavigate();
  const allSpaces = inAllSpaces(useSession());
  if (page.bundles.length === 0) {
    return (
      <EmptyState title="No policy bundle is available in this Space.">
        Admission fails closed until one is activated.
      </EmptyState>
    );
  }
  const { current, retired } = currentFirst(page.bundles);
  return (
    <Card>
      {current.length > 0 ? (
        <Table caption={allSpaces ? "Policy versions in the Spaces you can see, current ones first." : "Policy versions available in this Space, current ones first."}>
          <Head />
          <tbody>
            <BundleRows rows={current} />
          </tbody>
        </Table>
      ) : (
        <p className="muted">Every policy version here is retired.</p>
      )}
      {retired.length > 0 ? (
        <div className="policy-actions">
          <Button
            onClick={() => {
              void navigate({ to: "/policy", search: showRetired ? {} : { retired: 1 } });
            }}
          >
            {showRetired ? "Hide retired versions" : retiredToggle(retired.length)}
          </Button>
        </div>
      ) : null}
      {showRetired && retired.length > 0 ? (
        <Table caption="Retired policy versions, newest change first.">
          <Head />
          <tbody>
            <BundleRows rows={retired} />
          </tbody>
        </Table>
      ) : null}
    </Card>
  );
}

/**
 * A new draft: the JSON a person pastes, or a copy of the active bundle.
 *
 * Both are the one path on the server, so a bundle written as rules keeps them when copied.
 * Neither makes anything live: a draft is validated, previewed and activated as separate
 * steps, so this form needs no confirmation of its own.
 */
export function NewDraft({ hasActive, formAvailable = false, starterAvailable = false, starterHint = "" }: { hasActive: boolean; formAvailable?: boolean; starterAvailable?: boolean; starterHint?: string }) {
  // The document is kept in this tab across signing in again (#678).
  const session = useSession();
  const draft = usePolicyDraft(session.person.id);
  const { text: document, set: setDocument } = draft;
  useEffect(() => {
    if (draft.restored) toast("Your policy document was kept.");
  }, [draft.restored]);
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const create = useServerMutation({
    ...createPolicyBundleMutation(),
    onError: draft.refused,
    onSuccess: (made) => {
      draft.created();
      toast("Draft created. Validate it, then preview what it would change.");
      void queryClient.invalidateQueries({ queryKey: [{ _id: "listPolicy" }] });
      void navigate({ to: "/policy/$bundleId", params: { bundleId: made.bundle_id } });
    },
  });
  // A policy belongs to one Space. Under All spaces nothing here could be created, and "first
  // policy" would be wrong whenever another Space has one, so say what to do instead.
  if (inAllSpaces(session) && !draft.restored) {
    return (
      <Card title="New draft" className="new-draft">
        <p>
          A policy belongs to one Space. Choose a Space in the switcher at the top of the page to start a new
          policy or copy its active one. The versions below come from every Space you can see.
        </p>
      </Card>
    );
  }
  return (
    <Card title="New draft" className="new-draft">
      <p className="muted">
        A draft changes nothing. Validate it, preview what it would change, then activate it.
      </p>
      {!hasActive ? <section>
        <h3>Security response baseline</h3>
        <p>Start with the reviewed security response rules for your configured actions: incident-based permissions, protected-target denials, production approvals and target limits. Review the exact rules in the draft before activating it.</p>
        <Button variant="primary" disabled={create.isPending || !starterAvailable} onClick={() => {
          create.mutate({ body: { source: "template", template: "security-response" } });
        }}>Create first policy</Button>
        {!starterAvailable ? <p className="note">{starterHint || "Ask your deployment administrator to connect a protected endpoint or identity provider and register its action mappings. Then return here to create the first policy."}</p> : null}
      </section> : <div className="grid-2">
        <section>
          <h3>Current protections</h3>
          <p>Keep the current rules, approvals, connections, trusted context and target limits. Adjust common controls in a form.</p>
          <Button variant="primary" disabled={create.isPending || !formAvailable} onClick={() => {
            create.mutate({ body: { source: "template", template: "current-protections" } });
          }}>Customize current protections</Button>
        </section>
        <section>
          <h3>Review every allowed action</h3>
          <p>Keep existing protections and require a person to approve every action the policy allows. Denials still win.</p>
          <Button disabled={create.isPending || !formAvailable} onClick={() => {
            create.mutate({ body: { source: "template", template: "review-all" } });
          }}>Start with approval for every action</Button>
        </section>
      </div>}
      {hasActive && !formAvailable ? <p className="note">This policy has custom Cedar or controls the form cannot safely convert. Copy its complete configuration and inspect it under Advanced.</p> : null}
      <Problem error={create.error} />
      <RulesFileDraft />
      <details open={draft.restored || undefined}>
        <summary>Advanced: import or copy complete configuration</summary>
        <Field
        label="Bundle JSON"
        hint="The tenant and a new identity are filled in for you. At most 512 KB."
      >
        <textarea
          data-eb-kept=""
          value={document}
          rows={8}
          spellCheck={false}
          className="mono"
          onChange={(event) => {
            setDocument(event.target.value);
          }}
        />
      </Field>
      <div className="policy-actions">
        <Button
          variant="primary"
          disabled={create.isPending || document.trim() === ""}
          onClick={() => {
            create.mutate({ body: { source: "document", document } });
          }}
        >
          Create from JSON
        </Button>
        <Button
          disabled={create.isPending || !hasActive}
          title={hasActive ? undefined : "There is no active bundle to copy."}
          onClick={() => {
            create.mutate({ body: { source: "active" } });
          }}
        >
          Copy the active bundle
        </Button>
      </div>
      </details>
    </Card>
  );
}

export function CopyDraft({ bundleId, formAvailable }: { bundleId: string; formAvailable: boolean }) {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const create = useServerMutation({
    ...createPolicyBundleMutation(),
    onSuccess: (made) => {
      toast("Draft created. The live policy is unchanged.");
      void queryClient.invalidateQueries({ queryKey: [{ _id: "listPolicy" }] });
      void navigate({ to: made.written_as_rules ? "/policy/$bundleId/rules" : "/policy/$bundleId", params: { bundleId: made.bundle_id } });
    },
  });
  return <>
    <Button variant="primary" disabled={create.isPending} onClick={() => {
      create.mutate({ body: formAvailable
        ? { source: "template", bundle_id: bundleId, template: "current-protections" }
        : { source: "bundle", bundle_id: bundleId } });
    }}>{formAvailable ? "Create an editable draft" : "Copy complete configuration"}</Button>
    <Problem error={create.error} />
  </>;
}
