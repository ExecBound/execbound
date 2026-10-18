// SPDX-License-Identifier: AGPL-3.0-only
// Switching the space the session is looking at.
//
// The space travels in the **session**, as server state: one mutation names it, its argument
// is verified against membership inside the database, and there is no `?space=` anywhere, so
// editing a URL cannot ask for another space's rows. Nothing here decides anything; the
// server does, and this is the client following it.
//
// Switching **clears** the query cache rather than invalidating it. The generated
// client's query keys carry no space — the cookie carries the tenant and the session carries
// the space — and `lib/poll.ts` groups its subscriptions by the serialised key, so a response
// already in flight for the old space would land in the new space's cache under exactly the
// same key. An invalidate would also leave the old rows rendered while the refetch ran, which
// is one customer's rows under another customer's name. Cancelling and clearing is the only
// answer that cannot do that: every query is dropped and asked again under the new space.
//
// `queryClient.clear()` on its own is **not** that answer. Clearing removes each query from the
// cache, but a mounted observer keeps the removed query object until something rebuilds it, and
// a component that does not re-render never rebuilds one. The shell's own session query is
// exactly such an observer, so the sidebar and the breadcrumb went on naming the space the
// person had just left while every other read had already moved. `resetQueries()` is the one
// that keeps the guarantee: every cached row is discarded, so nothing of the old space is
// rendered while the new space's answer is on its way, and every live observer asks again.

import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef } from "react";

import { readSessionQueryKey, setSessionSpace } from "./shell-api";
import type { SessionView } from "../api/types.gen";
import { useServerMutation } from "./mutation";
import { useSession } from "./session";
import { toast } from "./toast";

/** What a switch is called afterwards, in the polite live region. */
export function switchedTo(name: string | null): string {
  return name === null ? "Showing all spaces." : `Now in ${name}.`;
}

/**
 * The one mutation, then the cache. `space` is a space id, or `null` for "All spaces".
 *
 * The fresh session view the route answers is written straight into the session query after
 * the clear, so the shell never falls back to its placeholder between the answer and the
 * next poll.
 */
export function useSpaceSwitch(onDone?: () => void) {
  const queryClient = useQueryClient();
  return useServerMutation<SessionView, { space: string | null; name: string | null }>({
    mutationFn: async ({ space }) => {
      const { data } = await setSessionSpace({ body: { space_id: space }, throwOnError: true });
      return data;
    },
    onSuccess: async (view, variables) => {
      await queryClient.cancelQueries();
      await queryClient.resetQueries();
      queryClient.setQueryData(readSessionQueryKey(), view);
      toast(switchedTo(variables.name));
      onDone?.();
    },
  });
}

/**
 * Follow one record into the space that owns it.
 *
 * A list is filtered by the space the person is looking at; a single record named by its own
 * identifier is authorised by membership and answered whatever the session holds, and its
 * answer says which space it came from. So an approval link opens the approval, and the shell
 * then moves the session to that space and says so, rather than showing a record from a space
 * the rest of the screen is not counting. Nothing happens for a session already in that space,
 * for one looking at "All spaces", or for a record whose space the answer did not name.
 */
export function useFollowSpace(space: { space_id: string; name: string } | null | undefined): void {
  const session = useSession();
  const switcher = useSpaceSwitch();
  const current = session.space?.id ?? null;
  const following = useRef<string | null>(null);
  const { mutate } = switcher;
  useEffect(() => {
    if (space === null || space === undefined) return;
    if (current === null || current === space.space_id) return;
    // One switch per record, however many times the polled detail answers again.
    if (following.current === space.space_id) return;
    following.current = space.space_id;
    mutate({ space: space.space_id, name: space.name });
  }, [space, current, mutate]);
}
