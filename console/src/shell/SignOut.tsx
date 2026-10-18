// SPDX-License-Identifier: AGPL-3.0-only
import { Button } from "../components/ui/Button";
import { useSession } from "../lib/session";
import { clearRecentWorkspaces } from "../lib/workspaces";

/**
 * Sign out, as a form the browser submits (#333).
 *
 * The session cookie is the gateway's, not the application's: ending it clears two cookies and
 * sends the person to `/login`, which is a navigation rather than a change to read back. So
 * this is the one control in the console that posts a form instead of calling the API — the
 * same `POST /session/logout` the pages have always used, with the session's own token in the
 * body, under `form-action 'self'`. Nothing is optimistic: the browser leaves when the server
 * answers. Every draft this tab kept, and the workspaces this browser opened last, are forgotten
 * before the browser posts (#678).
 */
export function SignOut({ className }: { className?: string }) {
  const csrf = useSession().csrf;
  // Before the session view arrives there is no token to send, so there is no button yet.
  if (csrf === "") return null;
  return (
    <form
      method="post"
      action="/session/logout"
      className={className}
      onSubmit={(event) => {
        // The drafts and the recent workspaces go first, then the browser posts; a store that
        // cannot load stops nothing.
        const form = event.currentTarget;
        event.preventDefault();
        clearRecentWorkspaces();
        void import("../lib/drafts").then(
          (store) => {
            store.clearDrafts();
            form.submit();
          },
          () => {
            form.submit();
          },
        );
      }}
    >
      <input type="hidden" name="csrf" value={csrf} />
      <Button type="submit">Sign out</Button>
    </form>
  );
}
