// SPDX-License-Identifier: AGPL-3.0-only
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useRef, useState } from "react";
import {
  readAccessOptions, setUserRolesMutation, createAccessGroupMutation,
  updateAccessGroupMutation, setGroupMembersMutation, setGroupRolesMutation,
  deleteAccessGroupMutation,
} from "../../api/@tanstack/react-query.gen";
import type { AccessGrant, AccessGroup, AccessPage, AccessUser } from "../../api/types.gen";
import { useServerMutation } from "../../lib/mutation";
import { toast } from "../../lib/toast";
import { Button } from "../ui/Button";
import { Card } from "../ui/Card";
import { EmptyState } from "../ui/EmptyState";
import { Table, Td, Th } from "../ui/Table";
import { ConfirmDialog } from "./ConfirmDialog";
import { explain } from "./errors";
import { Field } from "./forms";
import { principalName } from "./format";
import { PersonName } from "./PersonName";
import "./access.css";

/** A user as this page names them: label, else email, else "User 3". */
function nameOf(user: AccessUser): string {
  return principalName("User", user.label, user.number, user.principal_id, user.email);
}

export function grantName(grant: AccessGrant, data: AccessPage): string {
  const role = data.roles.find((item) => item.id === grant.role)?.name ?? grant.role;
  const scope = grant.space_id == null ? "Workspace" : data.spaces.find((item) => item.space_id === grant.space_id)?.name ?? "Archived Space";
  return `${role} · ${scope}`;
}

function useChanged(close?: () => void) {
  const cache = useQueryClient();
  return () => {
    toast("Access updated.");
    close?.();
    // Group membership and roles decide who can review, so decision coverage is stale too (#678).
    for (const id of ["readAccess", "readSession", "listPeople", "readPerson", "listApprovalRules", "listApproverScopes", "readApprovalCoverage", "readUnroutedApprovals"]) {
      void cache.invalidateQueries({ queryKey: [{ _id: id }] });
    }
  };
}

export function GrantPicker({ data, grants, onChange, group = false }: {
  data: AccessPage; grants: AccessGrant[]; onChange: (value: AccessGrant[]) => void; group?: boolean;
}) {
  return <div className="stack">
    {grants.length === 0 ? <p>{group ? "This group grants no roles. Add a role for its members to inherit." : "No direct roles. Access may still come from group membership."}</p> : null}
    {grants.map((grant, index) => <div className="filters" key={index}>
      <Field label={`Role ${String(index + 1)}`}><select aria-label={`Role ${String(index + 1)}`} value={grant.role} onChange={(event) => {
        const role = data.roles.find((item) => item.id === event.target.value)?.id;
        if (role !== undefined) onChange(grants.map((item, i) => i === index ? { role, space_id: role === "administrator" ? null : item.space_id } : item));
      }}>{data.roles.map((role) => <option key={role.id} value={role.id}>{role.name}</option>)}</select></Field>
      <Field label={`Scope ${String(index + 1)}`}><select aria-label={`Scope ${String(index + 1)}`} value={grant.space_id ?? ""} disabled={grant.role === "administrator"} onChange={(event) => {
        onChange(grants.map((item, i) => i === index ? { ...item, space_id: event.target.value || null } : item));
      }}><option value="">Entire workspace</option>{data.spaces.map((space) => <option key={space.space_id} value={space.space_id}>{space.name}</option>)}</select></Field>
      <Button aria-label={`Remove role ${String(index + 1)}`} onClick={() => { onChange(grants.filter((_, i) => i !== index)); }}>Remove</Button>
    </div>)}
    <Button disabled={grants.length >= 100} onClick={() => { onChange([...grants, { role: "viewer", space_id: null }]); }}>Add role</Button>
    <p className="note">Administrator applies to the whole workspace. Approver also needs an approval rule or individual review assignment.</p>
    {grants.some((grant) => grant.role === "administrator") ? <p className="note">Configure sign-in before granting Administrator; its sign-in recovery is managed by the installation owner.</p> : null}
  </div>;
}

export function UserRoleEditor({ data, user, onClose }: { data: AccessPage; user: AccessUser; onClose: () => void }) {
  const [grants, setGrants] = useState(user.direct_roles);
  const changed = useChanged(onClose);
  const save = useServerMutation({ ...setUserRolesMutation(), onSuccess: changed });
  return <ConfirmDialog open className="access-dialog" title={`Roles for ${nameOf(user)}`} confirm="Save roles"
    reason="Reason for this access change" pending={save.isPending} error={save.error} onClose={onClose}
    onConfirm={(reason) => { save.mutate({ path: { principal_id: user.principal_id }, body: { grants, reason } }); }}>
    {!user.managed ? <p>Saving replaces this user's existing access with the direct roles below. Group access remains additive.</p> : null}
    <h3>Direct roles</h3><GrantPicker data={data} grants={grants} onChange={setGrants} />
    {user.inherited_roles.length > 0 ? <><h3>Inherited from groups</h3><ul>{user.inherited_roles.map((grant, index) =>
      <li key={index}>{grantName(grant, data)} — {grant.group_name}</li>)}</ul><p>Change inherited roles or membership under Groups &amp; roles.</p></> : null}
    <p className="note">Changes apply to current sessions and pending work. At least one active workspace Administrator must remain.</p>
  </ConfirmDialog>;
}

export function AccessManagement() {
  const query = useQuery({ ...readAccessOptions(), refetchInterval: 30_000 });
  const [user, setUser] = useState<AccessUser | null>(null);
  if (query.data === undefined) return query.error ? <EmptyState title="Access could not be loaded.">{explain(query.error)}</EmptyState> : <p role="status">Loading access.</p>;
  const data = query.data;
  return <div className="stack">
    <Card title="Roles"><p>Roles control what users can do in this console. Agent action policies and approval routing are configured separately.</p>
      <dl>{data.roles.map((role) => <div key={role.id}><dt><strong>{role.name}</strong></dt><dd>{role.description}</dd></div>)}</dl>
    </Card>
    <Card title="Users and effective access"><p>Direct roles and group roles add together. Remove inherited access at its group.</p>
      <Table caption="User roles and their sources" density="compact"><thead><tr><Th>User</Th><Th>Direct roles</Th><Th>From groups</Th><Th>Manage</Th></tr></thead><tbody>
        {data.users.map((item) => <tr key={item.principal_id}><Td><PersonName id={item.principal_id} label={item.label} email={item.email} number={item.number} kind={item.kind} link />{!item.active ? " · Deactivated" : ""}</Td>
          <Td>{item.direct_roles.map((grant) => grantName(grant, data)).join("; ") || "None"}{!item.managed ? <small className="faint"> · Existing access</small> : null}</Td>
          <Td>{item.inherited_roles.map((grant) => `${grantName(grant, data)} (${grant.group_name})`).join("; ") || "None"}</Td>
          <Td><Button size="small" disabled={!item.active} onClick={() => { setUser(item); }}>Edit roles for {nameOf(item)}</Button></Td></tr>)}
      </tbody></Table>
    </Card>
    <div className="section-head"><h2>Groups</h2><GroupEditor data={data} /></div>
    {data.groups.length === 0 ? <EmptyState title="Create a group for a team.">Add users, assign roles, then use the group in Approval rules.</EmptyState> : null}
    {data.groups.map((group) => <Card key={group.group_id} title={group.name}><p>{group.description}</p>
      <p>{group.members.length} {group.members.length === 1 ? "user" : "users"} · {group.roles.map((grant) => grantName(grant, data)).join("; ") || "No group roles"}</p>
      <div className="actions"><GroupEditor data={data} group={group} /><GroupMembersEditor data={data} group={group} /><GroupRolesEditor data={data} group={group} /><DeleteGroup group={group} /></div>
    </Card>)}
    <p className="note"><Link to="/approvers">Manage Approval rules</Link> to choose the actions and resources each reviewer group can review.</p>
    {user !== null ? <UserRoleEditor key={user.principal_id} data={data} user={user} onClose={() => { setUser(null); }} /> : null}
  </div>;
}

function GroupEditor({ group }: { data: AccessPage; group?: AccessGroup }) {
  const nameField = useRef<HTMLInputElement>(null);
  const [open, setOpen] = useState(false);
  const [name, setName] = useState(group?.name ?? "");
  const [description, setDescription] = useState(group?.description ?? "");
  const close = () => { setOpen(false); };
  const changed = useChanged(close);
  const create = useServerMutation({ ...createAccessGroupMutation(), onSuccess: changed });
  const update = useServerMutation({ ...updateAccessGroupMutation(), onSuccess: changed });
  return <><Button onClick={() => {
    setName(group?.name ?? ""); setDescription(group?.description ?? "");
    create.reset(); update.reset(); setOpen(true);
  }}>{group ? "Edit group" : "Create group"}</Button>
    {open ? <ConfirmDialog open initialFocus={nameField} className="access-dialog" title={group ? `Edit ${group.name}` : "Create group"} confirm={group ? "Save group" : "Create group"}
      reason="Reason for this change" pending={create.isPending || update.isPending} error={create.error ?? update.error}
      confirmDisabled={name.trim() === ""} onClose={close} onConfirm={(reason) => {
        const body = { name: name.trim(), description: description.trim() || null, reason };
        if (group) update.mutate({ path: { group_id: group.group_id }, body }); else create.mutate({ body });
      }}><Field label="Group name"><input ref={nameField} value={name} maxLength={80} onChange={(event) => { setName(event.target.value); }} /></Field>
      <Field label="Description"><textarea value={description} maxLength={240} onChange={(event) => { setDescription(event.target.value); }} /></Field>
      <p>{group ? "Manage this group's membership and inherited access with Edit members and Edit group roles." : "A new group starts with no members or roles."}</p>
    </ConfirmDialog> : null}</>;
}

function DeleteGroup({ group }: { group: AccessGroup }) {
  const [open, setOpen] = useState(false);
  const changed = useChanged(() => { setOpen(false); });
  const remove = useServerMutation({ ...deleteAccessGroupMutation(), onSuccess: changed });
  return <><Button onClick={() => { remove.reset(); setOpen(true); }}>Delete group</Button>
    {open ? <ConfirmDialog open title={`Delete ${group.name}?`} confirm="Delete group" danger
      reason="Reason for deleting" pending={remove.isPending} error={remove.error}
      confirmDisabled={group.members.length > 0 || group.roles.length > 0}
      onClose={() => { setOpen(false); }} onConfirm={(reason) => { remove.mutate({ path: { group_id: group.group_id }, body: { reason } }); }}>
      <p>Remove all members and roles, then disable this group's approval rules before deleting it.</p>
      <p>Deletion also removes its disabled approval rules. Audit history remains. This cannot be undone.</p>
    </ConfirmDialog> : null}</>;
}

function GroupMembersEditor({ data, group }: { data: AccessPage; group: AccessGroup }) {
  const [open, setOpen] = useState(false);
  const [members, setMembers] = useState(group.members);
  const changed = useChanged(() => { setOpen(false); });
  const save = useServerMutation({ ...setGroupMembersMutation(), onSuccess: changed });
  return <><Button onClick={() => { setMembers(group.members); save.reset(); setOpen(true); }}>Edit members</Button>
    {open ? <ConfirmDialog open className="access-dialog" title={`Members of ${group.name}`} confirm="Save members" reason="Reason for this change" pending={save.isPending} error={save.error}
      onClose={() => { setOpen(false); }} onConfirm={(reason) => { save.mutate({ path: { group_id: group.group_id }, body: { members, reason } }); }}>
      <p>Members inherit group roles and eligible approval rules. Their direct access remains in place.</p>
      <div className="stack">{data.users.filter((user) => user.active || members.includes(user.principal_id)).map((user) => <label key={user.principal_id}>
        <input type="checkbox" checked={members.includes(user.principal_id)} onChange={(event) => {
          setMembers(event.target.checked ? [...members, user.principal_id] : members.filter((id) => id !== user.principal_id));
        }} /> {nameOf(user)}{!user.active ? " (deactivated)" : ""}
      </label>)}</div>
    </ConfirmDialog> : null}</>;
}

function GroupRolesEditor({ data, group }: { data: AccessPage; group: AccessGroup }) {
  const [open, setOpen] = useState(false);
  const [grants, setGrants] = useState(group.roles);
  const changed = useChanged(() => { setOpen(false); });
  const save = useServerMutation({ ...setGroupRolesMutation(), onSuccess: changed });
  return <><Button onClick={() => { setGrants(group.roles); save.reset(); setOpen(true); }}>Edit group roles</Button>
    {open ? <ConfirmDialog open className="access-dialog" title={`Roles for ${group.name}`} confirm="Save group roles" reason="Reason for this change" pending={save.isPending} error={save.error}
      onClose={() => { setOpen(false); }} onConfirm={(reason) => { save.mutate({ path: { group_id: group.group_id }, body: { grants, reason } }); }}>
      <p>This changes inherited access for {group.members.length} {group.members.length === 1 ? "user" : "users"}.</p><GrantPicker data={data} grants={grants} onChange={setGrants} group />
    </ConfirmDialog> : null}</>;
}
