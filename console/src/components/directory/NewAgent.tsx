// SPDX-License-Identifier: AGPL-3.0-only
import { useInfiniteQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { useState } from "react";

import { createAgentMutation } from "../../api/@tanstack/react-query.gen";
import { listSpaces } from "../../api/sdk.gen";
import { useCommand } from "../../lib/commands";
import { useServerMutation } from "../../lib/mutation";
import { useSession } from "../../lib/session";
import { useSpaceSwitch } from "../../lib/spaces";
import { toast } from "../../lib/toast";
import { Button } from "../ui/Button";
import { AGENT_HOSTS, isAgentHost, saveAgentHost, type AgentHost } from "../welcome/agent-host";
import { ConfirmDialog } from "./ConfirmDialog";
import { Field, Problem } from "./forms";

export function NewAgent() {
  const [open, setOpen] = useState(false);
  // The palette's Add agent opens this dialog as the button would (#678).
  useCommand("add-agent", () => { setOpen(true); });
  return <>
    <Button variant="primary" onClick={() => { setOpen(true); }}>Add agent</Button>
    {open ? <NewAgentDialog onClose={() => { setOpen(false); }} /> : null}
  </>;
}

function NewAgentDialog({ onClose }: { onClose: () => void }) {
  const session = useSession();
  const navigate = useNavigate();
  const cache = useQueryClient();
  const [step, setStep] = useState<"host" | "identity">("host");
  const [host, setHost] = useState<AgentHost | "">("");
  const [label, setLabel] = useState("");
  const [space, setSpace] = useState(session.space?.archived === false ? session.space.id : "");
  const [filter, setFilter] = useState("");
  const spaces = useInfiniteQuery({
    queryKey: ["agent-creation-spaces", filter],
    initialPageParam: undefined as string | undefined,
    queryFn: async ({ pageParam }) => {
      const { data } = await listSpaces({
        query: { state: "active", ...(filter.trim() ? { q: filter.trim() } : {}), ...(pageParam ? { cursor: pageParam } : {}) },
        throwOnError: true,
      });
      return data;
    },
    getNextPageParam: (page) => page.next_cursor ?? undefined,
  });
  const rows = spaces.data?.pages.flatMap((page) => page.items) ?? [];
  const selected = rows.find((row) => row.space_id === space);
  const switcher = useSpaceSwitch();
  const create = useServerMutation({
    ...createAgentMutation(),
    onSuccess: (made) => {
      if (host !== "") saveAgentHost(made.principal_id, host);
      toast("Agent created. Connect its host, review Permissions, then verify a request.");
      void cache.invalidateQueries({ queryKey: [{ _id: "listAgents" }] });
      onClose();
      void navigate({ to: "/agents/$agentId", params: { agentId: made.principal_id }, search: { section: "connection" } });
    },
  });
  const pending = switcher.isPending || create.isPending;
  return <ConfirmDialog
    open title={step === "host" ? "Add agent · Choose host" : "Add agent · Name and Space"}
    confirm={step === "host" ? "Continue" : "Create agent and connect"}
    pending={pending}
    confirmDisabled={step === "host" ? host === "" : label.trim() === "" || selected === undefined}
    error={switcher.error ?? create.error}
    onClose={onClose}
    onConfirm={() => {
      if (step === "host") { setStep("identity"); return; }
      if (selected === undefined || host === "") return;
      // The only Space-bearing request is the existing membership-checked session switch.
      // Always select again, including the current Space: do not create after a refused switch.
      void switcher.mutateAsync({ space: selected.space_id, name: selected.name })
        .then(() => create.mutateAsync({ body: { label: label.trim() } }))
        .catch(() => { /* The owning mutation renders the refusal and preserves input. */ });
    }}
  >
    {step === "host" ? <>
      <p>Choose where your agent runs. Next, name it and choose its Space.</p>
      <Field label="Agent host"><select aria-label="Agent host" value={host} onChange={(event) => { if (isAgentHost(event.target.value)) setHost(event.target.value); }}>
        <option value="" disabled>Choose a supported host</option>
        {AGENT_HOSTS.map(([value, name]) => <option key={value} value={value}>{name}</option>)}
      </select></Field>
      <p className="note">These clients connect over MCP with the agent's API key. Claude Desktop and claude.ai need OAuth, which is not available here yet.</p>
    </> : <>
      <p>{AGENT_HOSTS.find(([value]) => value === host)?.[1]} · <Button variant="ghost" disabled={pending} onClick={() => { setStep("host"); }}>Back</Button></p>
      <Field label="Agent name" hint="Use its purpose or team name; up to 80 characters.">
        <input aria-label="Agent name" value={label} maxLength={80} autoComplete="off" required disabled={pending} onChange={(event) => { setLabel(event.target.value); }} />
      </Field>
      <Field label="Find a Space"><input aria-label="Find a Space" value={filter} maxLength={80} disabled={pending} onChange={(event) => { setFilter(event.target.value); }} /></Field>
      <Field label="Space" hint="The agent uses this Space’s selected policy. Creating it also switches your current Space.">
        <select aria-label="Space" value={space} required disabled={pending || spaces.isPending} onChange={(event) => { setSpace(event.target.value); }}>
          <option value="" disabled>Choose a Space</option>
          {rows.map((row) => <option key={row.space_id} value={row.space_id}>{row.name}</option>)}
        </select>
      </Field>
      {spaces.isPending ? <p role="status">Loading Spaces…</p> : null}
      {!spaces.isPending && rows.length === 0 ? <p>No active Space matches. Change the search or create a Space from the sidebar.</p> : null}
      {spaces.hasNextPage ? <Button disabled={spaces.isFetchingNextPage} onClick={() => { void spaces.fetchNextPage(); }}>Load more Spaces</Button> : null}
      <Problem error={spaces.error} />
      <p className="note">Next: create an API key, configure {AGENT_HOSTS.find(([value]) => value === host)?.[1]}, review Permissions, and verify a governed request.</p>
    </>}
  </ConfirmDialog>;
}
