// SPDX-License-Identifier: AGPL-3.0-only
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useRef, useState } from "react";
import {
  listApprovalRulesOptions, readAccessOptions, listApproverScopesOptions,
  createApprovalRuleMutation, updateApprovalRuleMutation, disableApprovalRuleMutation,
} from "../../api/@tanstack/react-query.gen";
import { useSession } from "../../lib/session";
import type { AccessPage, ApprovalRule, ApprovalRulesPage, ApproversPage } from "../../api/types.gen";
import { useServerMutation } from "../../lib/mutation";
import { toast } from "../../lib/toast";
import { Button } from "../ui/Button";
import { Card } from "../ui/Card";
import { EmptyState } from "../ui/EmptyState";
import { ApproversList, AssignScope, type AssignPreset } from "./ApproversList";
import { DecisionCoverage, type Gap } from "./DecisionCoverage";
import { ConfirmDialog } from "./ConfirmDialog";
import { explain } from "./errors";
import { Field } from "./forms";
import { prefix } from "./format";
import "./access.css";

/** A rule dialog the coverage card opened: an existing rule or a new one, with the gap's target. */
interface Fix {
  rule: ApprovalRule | null;
  preset: RulePreset;
}

export function ApprovalRules() {
  const rules = useQuery({ ...listApprovalRulesOptions(), refetchInterval: 30_000 });
  const access = useQuery({ ...readAccessOptions(), refetchInterval: 30_000 });
  const scopes = useQuery(listApproverScopesOptions());
  const session = useSession();
  const [fix, setFix] = useState<Fix | null>(null);
  const [assigning, setAssigning] = useState<AssignPreset | null>(null);
  const data = rules.data;
  if (data === undefined || access.data === undefined || scopes.data === undefined) {
    const error = rules.error ?? access.error ?? scopes.error;
    return error ? <EmptyState title="Approval rules could not be loaded.">{explain(error)}</EmptyState> : <p role="status">Loading approval rules.</p>;
  }
  const team = access.data;
  const assignments = scopes.data;
  // An individual assignment lands in the Space the session is looking at, or the workspace's
  // only one; with several and "All spaces" it is ambiguous, and the card says to switch first.
  const writeSpace = session.space?.id ?? (team.spaces.length === 1 ? team.spaces[0]?.space_id ?? null : null);
  const addToRule = (gap: Gap, rule: ApprovalRule | null) => {
    setFix({ rule, preset: { space_id: gap.space_id, actions: [gap.action], targets: [gap.target] } });
  };
  return <div className="stack">
    <DecisionCoverage rules={data.rules} writeSpace={writeSpace} onAddToRule={addToRule}
      onAssign={(gap) => { setAssigning({ target: gap.target, action: gap.action }); }} />
    {fix !== null ? <RuleEditor key={`${fix.rule?.rule_id ?? "new"}-${fix.preset.targets?.[0]?.id ?? ""}`} data={data} access={team} scopes={assignments}
      rule={fix.rule ?? undefined} preset={fix.preset} open onOpenChange={(open) => { if (!open) setFix(null); }} /> : null}
    {assigning !== null ? <AssignScope key={`${assigning.target?.id ?? ""}-${assigning.action ?? ""}`} data={assignments} preset={assigning}
      open onOpenChange={(open) => { if (!open) setAssigning(null); }} /> : null}
    <Card title="Choose who reviews an action">
      <ol className="links"><li>Create a <Link to="/access">reviewer group</Link> and give its users the Approver role.</li>
        <li>Choose the Space, actions and resources the group may review.</li>
        <li>Policy decides when approval is required. The rule routes those requests to eligible reviewers.</li></ol>
      <p className="note">Approval never overrides a policy denial. Group membership, roles and review scope are checked again before execution.</p>
    </Card>
    <div className="section-head"><h2>Group rules</h2><RuleEditor data={data} access={team} scopes={assignments} /></div>
    {data.rules.length === 0 ? <EmptyState title="No group rules yet.">Existing individual assignments below continue to work. A group rule replaces repeated user-by-resource assignments.</EmptyState> : null}
    {team.groups.length === 0 ? <p className="note"><Link to="/access">Create a reviewer group</Link> to add your first group rule.</p> : null}
    {data.rules.map((rule) => <RuleCard key={rule.rule_id} rule={rule} data={data} access={team} scopes={assignments} />)}
    <details><summary>Advanced: individual review assignments ({assignments.assignments.length})</summary>
      <p>Use individual assignments for exceptions. Removing a group rule does not remove these separate assignments.</p>
      <AssignScope data={assignments} /><ApproversList data={assignments} />
    </details>
  </div>;
}

function useRuleChanged(close: () => void) {
  const cache = useQueryClient();
  return () => {
    toast("Approval rules updated."); close();
    for (const id of ["listApprovalRules", "listApproverScopes", "readPerson", "readBoard", "listApprovals", "readApprovalCoverage", "readUnroutedApprovals"]) {
      void cache.invalidateQueries({ queryKey: [{ _id: id }] });
    }
  };
}

function RuleCard({ rule, data, access, scopes }: { rule: ApprovalRule; data: ApprovalRulesPage; access: AccessPage; scopes: ApproversPage }) {
  const [disable, setDisable] = useState(false);
  const changed = useRuleChanged(() => { setDisable(false); });
  const save = useServerMutation({ ...disableApprovalRuleMutation(), onSuccess: changed });
  const names = rule.actions.map((action) => data.actions.find((item) => item.id === action)?.name ?? action);
  return <Card title={rule.name}>
    <p><strong>{rule.active ? "Active" : "Disabled"}</strong> · {rule.active ? <>{rule.group_name} may review </> : <>This rule grants no review authority. Saved configuration: {rule.group_name} · </>}<strong>{names.join(", ")}</strong> on {rule.targets.length} selected {rule.targets.length === 1 ? "resource" : "resources"} in <strong>{rule.space_name}</strong>.</p>
    <p>{rule.eligible_reviewers} eligible {rule.eligible_reviewers === 1 ? "reviewer" : "reviewers"}{rule.active && rule.eligible_reviewers === 0 ? " — add group members with the Approver role in this Space." : "."}</p>
    <details><summary>Selected resources</summary><ul>{rule.targets.map((target) => <li key={target}>{scopes.targets.find((item) => item.canonical_target_id === target)?.labels ?? prefix(target)}</li>)}</ul></details>
    <div className="actions"><RuleEditor data={data} access={access} scopes={scopes} rule={rule} />
      {rule.active ? <Button onClick={() => { save.reset(); setDisable(true); }}>Disable rule</Button> : null}</div>
    {disable ? <ConfirmDialog open className="access-dialog" title={`Disable ${rule.name}?`} confirm="Disable rule" danger reason="Reason for disabling" pending={save.isPending} error={save.error}
      onClose={() => { setDisable(false); }} onConfirm={(reason) => { save.mutate({ path: { rule_id: rule.rule_id }, body: { reason } }); }}>
      <p>Reviewers lose this rule's authority immediately, including for already approved work awaiting execution. Other applicable rules and individual assignments remain.</p>
    </ConfirmDialog> : null}
  </Card>;
}

/** A preview from the current directory snapshot; the server rechecks authority on use. */
export function eligibleReviewers(access: AccessPage, groupId: string, spaceId: string): number {
  const group = access.groups.find((item) => item.group_id === groupId);
  if (group === undefined || spaceId === "") return 0;
  return access.users.filter((user) => user.active && group.members.includes(user.principal_id) && [
    ...user.direct_roles,
    ...access.groups.filter((item) => item.members.includes(user.principal_id)).flatMap((item) => item.roles),
  ].some((grant) => access.roles.find((role) => role.id === grant.role)?.permissions.includes("approvals.decide") &&
    (grant.space_id == null || grant.space_id === spaceId))).length;
}

/**
 * What the coverage card asks the rule dialog to start from: the Space, the action and the
 * gap's target with its labels, merged over the rule's own values. A target the approvers
 * page's list does not hold is added to the options, so it is shown, checked and sent.
 */
export interface RulePreset {
  space_id?: string;
  actions?: string[];
  targets?: { id: string; labels: string | null }[];
}

function union(base: string[], extra: string[] | undefined): string[] {
  return [...base, ...(extra ?? []).filter((item) => !base.includes(item))];
}

function RuleEditor({ data, access, scopes, rule, preset, open: controlled, onOpenChange }: {
  data: ApprovalRulesPage; access: AccessPage; scopes: ApproversPage; rule?: ApprovalRule;
  preset?: RulePreset; open?: boolean; onOpenChange?: (open: boolean) => void;
}) {
  const nameField = useRef<HTMLInputElement>(null);
  const initial = {
    name: rule?.name ?? "",
    group: rule?.group_id ?? "",
    space: rule?.space_id ?? preset?.space_id ?? "",
    actions: union(rule?.actions ?? [], preset?.actions),
    targets: union(rule?.targets ?? [], preset?.targets?.map((item) => item.id)),
  };
  const [own, setOwn] = useState(false);
  const open = controlled ?? own;
  const setOpen = (value: boolean) => { if (controlled === undefined) setOwn(value); onOpenChange?.(value); };
  const [name, setName] = useState(initial.name);
  const [group, setGroup] = useState(initial.group);
  const [space, setSpace] = useState(initial.space);
  const [actions, setActions] = useState<string[]>(initial.actions);
  const [targets, setTargets] = useState<string[]>(initial.targets);
  const [filter, setFilter] = useState("");
  const changed = useRuleChanged(() => { setOpen(false); });
  const create = useServerMutation({ ...createApprovalRuleMutation(), onSuccess: changed });
  const update = useServerMutation({ ...updateApprovalRuleMutation(), onSuccess: changed });
  const ready = name.trim() !== "" && group !== "" && space !== "" && actions.length > 0 && targets.length > 0 && targets.length <= 100;
  const eligible = eligibleReviewers(access, group, space);
  const options = [
    ...(preset?.targets ?? [])
      .filter((item) => !scopes.targets.some((known) => known.canonical_target_id === item.id))
      .map((item) => ({ canonical_target_id: item.id, labels: item.labels })),
    ...scopes.targets,
  ];
  const matching = options.filter((item) => `${item.labels ?? ""} ${item.canonical_target_id}`.toLowerCase().includes(filter.toLowerCase()));
  return <>{controlled === undefined ? <Button disabled={access.groups.length === 0} onClick={() => {
    setName(initial.name); setGroup(initial.group); setSpace(initial.space);
    setActions(initial.actions); setTargets(initial.targets); setFilter("");
    create.reset(); update.reset(); setOpen(true);
  }}>{rule ? "Edit rule" : "Create approval rule"}</Button> : null}
    {open ? <ConfirmDialog open initialFocus={nameField} className="access-dialog" title={rule ? `Edit ${rule.name}` : "Create approval rule"} confirm={rule?.active === false ? "Save and enable rule" : "Save rule"}
      reason="Reason for this rule change" pending={create.isPending || update.isPending} error={create.error ?? update.error} confirmDisabled={!ready}
      onClose={() => { setOpen(false); }} onConfirm={(reason) => {
        const body = { name: name.trim(), group_id: group, space_id: space, actions, targets, reason };
        if (rule) update.mutate({ path: { rule_id: rule.rule_id }, body }); else create.mutate({ body });
      }}>
      <Field label="Rule name"><input ref={nameField} maxLength={80} value={name} onChange={(event) => { setName(event.target.value); }} placeholder="Production endpoint response" /></Field>
      <Field label="Reviewer group"><select value={group} onChange={(event) => { setGroup(event.target.value); }}><option value="">Choose a group</option>{access.groups.map((item) => <option key={item.group_id} value={item.group_id}>{item.name}</option>)}</select></Field>
      <Field label="Space"><select value={space} onChange={(event) => { setSpace(event.target.value); }}><option value="">Choose a Space</option>{access.spaces.map((item) => <option key={item.space_id} value={item.space_id}>{item.name}</option>)}</select></Field>
      {group !== "" && space !== "" ? <div role="status">
        <p><strong>{eligible} eligible {eligible === 1 ? "reviewer" : "reviewers"} in {access.spaces.find((item) => item.space_id === space)?.name}</strong></p>
        {eligible === 0 ? <p>No eligible reviewers. Add active users to this group and give them the Approver role for this Space or the workspace. Saving now will not make anyone able to review these requests.</p> : null}
        <p className="note">Based on current membership and roles. Eligibility is checked again when a request is reviewed and before execution.</p>
      </div> : <p className="note">Choose a group and Space to preview eligible reviewers.</p>}
      <fieldset><legend>Actions they may review</legend>{data.actions.map((action) => <label className="check-line" key={action.id}><input type="checkbox" checked={actions.includes(action.id)} onChange={(event) => {
        setActions(event.target.checked ? [...actions, action.id] : actions.filter((id) => id !== action.id));
      }} /> {action.name}</label>)}</fieldset>
      <fieldset><legend>Resources ({targets.length} selected; up to 100)</legend>
        <Field label="Find a resource"><input type="search" value={filter} onChange={(event) => { setFilter(event.target.value); }} /></Field>
        {matching.length === 0 ? <p>No matching resources. Try a different name or ID.</p> : null}
        <div className="access-resource-picker">{matching.map((target) => <label className="check-line" key={target.canonical_target_id}><input type="checkbox" checked={targets.includes(target.canonical_target_id)} disabled={targets.length >= 100 && !targets.includes(target.canonical_target_id)} onChange={(event) => {
          setTargets(event.target.checked ? [...targets, target.canonical_target_id] : targets.filter((id) => id !== target.canonical_target_id));
        }} /> {target.labels ?? "Unnamed resource"} <small className="mono faint">{prefix(target.canonical_target_id)}</small></label>)}</div>
        <p className="note">Only selected resources are included. Newly discovered resources require an explicit rule update.</p>
      </fieldset>
    </ConfirmDialog> : null}</>;
}
