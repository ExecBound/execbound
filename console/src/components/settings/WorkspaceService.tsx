// SPDX-License-Identifier: AGPL-3.0-only
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { readAccountRequestsOptions, readAccountRequestsQueryKey, resolveAccountRequestMutation } from "../../api/@tanstack/react-query.gen";
import type { QueuedRequest } from "../../api/types.gen";
import { useEdition } from "../../edition/context";
import { useServerMutation } from "../../lib/mutation";
import { copyFor } from "../../lib/refusal";
import { can, useService, useSession } from "../../lib/session";
import { when } from "../../lib/when";
import { PrincipalName } from "../PrincipalName";
import { Button } from "../ui/Button";
import { Card } from "../ui/Card";
import { FormDialog } from "../ui/FormDialog";
import { REQUEST_LABELS } from "./AccountDetails";

/**
 * Workspace settings' service cards: the workspace's data and closure requests, and after them
 * whatever the console's edition adds (#496), which on the hosted service is the plan
 * and the optional product counts.
 *
 * The requests come from every space, with each requester's name, so only a workspace
 * administrator reads and answers them (decided 8 October 2026): an administrator narrowed to
 * spaces, who lacks workspace-wide `access.manage`, is shown a note in place of the queue, and
 * the queue is not read for them.
 */
export function WorkspaceService() {
  const { WorkspacePanels } = useEdition();
  const workspace = can(useSession(), "access.manage");
  return <>{workspace ? <PrivacyQueue /> : <PrivacyQueueNote />}<WorkspacePanels /></>;
}

/** What a narrowed administrator is told in place of the queue. */
function PrivacyQueueNote() {
  return <Card title="Data and closure requests"><p className="note">Only a workspace administrator reads and answers these requests, because they come from every space.</p></Card>;
}

function PrivacyQueue() {
  const query = useQuery(readAccountRequestsOptions());
  // The deployment's own request-handling guidance (#496), where it names a page for it.
  const { privacy_requests_url: guidance } = useService();
  const cache = useQueryClient();
  const [selected, setSelected] = useState<QueuedRequest | null>(null);
  const [response, setResponse] = useState("");
  const [state, setState] = useState<"completed" | "declined">("completed");
  const change = useServerMutation({ ...resolveAccountRequestMutation(), onSuccess: () => { setSelected(null); void cache.invalidateQueries({ queryKey: readAccountRequestsQueryKey() }); } });
  return <Card title="Data and closure requests"><p>Workspace administrators own this queue. Verify the requester, agree the scope, carry out the work, then record the result. Closing a ticket here does not delete accounts, erase data or produce an export.</p>
    {guidance !== null ? <p><a href={guidance}>Request-handling guidance and escalation</a></p> : null}
    {/* Only a first read that failed shows it; a later read that fails leaves the queue it read. */}
    {query.data === undefined ? query.isError ? <p role="alert">Requests could not be loaded. <Button onClick={() => { void query.refetch(); }}>Try again</Button></p> : <p role="status">Loading requests…</p> : query.data.length ? <ul>{query.data.map((item) => <li key={item.request_id}><strong>{REQUEST_LABELS[item.kind]}</strong> · <PrincipalName principal={{ principal_id: item.principal_id, label: item.name, number: item.number, kind: item.principal_kind }} /> · {item.state}<p className="muted">{when(item.requested_at)}</p>{item.state === "pending" ? <Button onClick={() => { setSelected(item); setResponse(""); setState("completed"); change.reset(); }}>Record response</Button> : <p>{item.response}</p>}</li>)}</ul> : <p>No requests yet.</p>}
    <FormDialog open={selected !== null} onClose={() => { setSelected(null); }} title="Record the request outcome" description="Only mark completed after the requested work has been performed. The requester can read your response in My account."
      confirm="Save response" pending={change.isPending} error={change.isError ? copyFor(change.error) : undefined}
      onSubmit={() => { if (selected) change.mutate({ body: { request_id: selected.request_id, state, response } }); }}>
      <label className="field"><span className="field-label">Outcome</span><select value={state} onChange={(event) => { setState(event.target.value as "completed" | "declined"); }}><option value="completed">Completed</option><option value="declined">Declined</option></select></label>
      <label className="field"><span className="field-label">Response and completion evidence</span><textarea required minLength={1} maxLength={1000} value={response} onChange={(event) => { setResponse(event.target.value); }} /></label>
      <p className="muted">Describe what was done and any retention limits. Do not paste secrets or the data export itself.</p>
    </FormDialog>
  </Card>;
}
