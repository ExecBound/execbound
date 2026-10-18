// SPDX-License-Identifier: AGPL-3.0-only
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useState } from "react";

import { readAccessOptions } from "../../api/@tanstack/react-query.gen";
import type { AccessPage, AccessUser } from "../../api/types.gen";
import { Button } from "../ui/Button";
import { Card } from "../ui/Card";
import { grantName, UserRoleEditor } from "./AccessManagement";
import { Problem } from "./forms";

/** One cached access read per page, shared with Groups & roles and its editors. */
export function useUserAccess() {
  return useQuery({ ...readAccessOptions(), staleTime: 30_000, refetchInterval: 30_000, retry: false });
}

export type AccountProtection = "protected" | "standard" | "unknown";

export function UserRoleSummary({ data, user }: { data: AccessPage; user: AccessUser }) {
  return <>
    <div aria-label="Direct roles">
      {user.direct_roles.length === 0 ? <span>No direct roles</span> : user.direct_roles.map((grant, index) => <div key={index}>{grantName(grant, data)}</div>)}
      {!user.managed ? <small className="faint">Existing access</small> : null}
    </div>
    <div aria-label="Inherited roles">
      {user.inherited_roles.length === 0 ? <span className="faint">No group roles</span> : user.inherited_roles.map((grant, index) => <div key={index}>{grantName(grant, data)} · from {grant.group_name}</div>)}
    </div>
  </>;
}

export function UserAccessLinks() {
  return <p><Link to="/access">Groups &amp; roles</Link> · <Link to="/approvers">Approval rules</Link></p>;
}

export function UserAccessCard({ principalId, query }: { principalId: string; query: ReturnType<typeof useUserAccess> }) {
  const [editing, setEditing] = useState(false);
  const data = query.data;
  const user = data?.users.find((item) => item.principal_id === principalId);
  return <Card title="Roles and access" aria-label="Roles and access">
    <p>Direct roles and group roles add together. Approval rules separately define which actions and resources a user may review.</p>
    {data !== undefined && user !== undefined ? <>
      <UserRoleSummary data={data} user={user} />
      <div className="row"><Button disabled={!user.active} onClick={() => { setEditing(true); }}>Edit roles</Button></div>
      {editing ? <UserRoleEditor key={user.principal_id} data={data} user={user} onClose={() => { setEditing(false); }} /> : null}
    </> : query.isPending ? <p role="status">Loading roles…</p> : <p>Role assignments are unavailable. Refresh access before making changes.</p>}
    <Problem error={query.error} />
    <UserAccessLinks />
  </Card>;
}
