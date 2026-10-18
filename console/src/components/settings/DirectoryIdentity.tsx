// SPDX-License-Identifier: AGPL-3.0-only
import type { PersonalSettingsView } from "../../api/types.gen";
import { useSession } from "../../lib/session";
import { when } from "../../lib/when";
import { Badge } from "../ui/Badge";
import { Button } from "../ui/Button";
import { Card } from "../ui/Card";
import { Definition, Definitions } from "../ui/Definitions";

const VIA_WORDS: Record<string, string> = {
  self: "You linked it yourself",
  admin: "An administrator linked it",
  invitation: "You redeemed an invitation",
};

/**
 * Directory identity (#253, #241): the account this person holds at the workspace's own
 * directory, how it was linked and when it last signed in, or, when there is none and the
 * workspace has an enabled provider, `Link my identity`.
 *
 * The subject and the two display hints are the directory's text, not this application's, so
 * each is rendered as text and nothing here builds markup or an address from them. The button
 * is a navigation rather than a fetch, as on tenant settings: the flow leaves for the directory
 * and comes back, and the session cookie is what says who is linking. The server offers a
 * provider only when it is enabled and the deployment serves the directory routes, so the
 * button never leads to a refusal the page could have known about.
 *
 * Who removes a link depends on who is looking. `directory_unlink` takes an approver's link
 * alone, refusing a principal whose kind or effective kind is an administrator's, so an
 * approver is unlinked by an administrator on their page under Users and an administrator from
 * no console page at all. The session's role is `ADMIN` exactly when the effective kind the
 * server resolved for it is.
 */
export function DirectoryIdentity({ directory }: { directory: PersonalSettingsView["directory"] }) {
  const { provider, link } = directory;
  const administrator = useSession().role === "ADMIN";
  return (
    <Card title="Directory identity">
      {link !== null ? (
        <>
          <p>
            <Badge tone="allow">Linked</Badge> <span>{link.provider_name}</span>
          </p>
          <Definitions aria-label="Directory identity">
            <Definition term="Subject" mono>
              {link.subject}
            </Definition>
            {link.display_name !== null ? <Definition term="Name">{link.display_name}</Definition> : null}
            {link.display_username !== null ? (
              <Definition term="Username">{link.display_username}</Definition>
            ) : null}
            <Definition term="How">{VIA_WORDS[link.via] ?? link.via}</Definition>
            <Definition term="Linked on" mono>
              {when(link.created_at)}
            </Definition>
            <Definition term="Last sign-in" mono>
              {link.last_sign_in_at !== null ? when(link.last_sign_in_at) : "None yet"}
            </Definition>
          </Definitions>
          {provider?.provider_id !== link.provider_id ? (
            <p className="note">Signing in through this directory is not enabled in this workspace right now.</p>
          ) : null}
        </>
      ) : provider !== null ? (
        <>
          <p className="muted">
            Link the account you hold at <span>{provider.name}</span> to sign in to this workspace with it. You
            sign in there once and come back here; nothing else about your account changes.
          </p>
          <div className="row">
            <Button
              variant="primary"
              onClick={() => {
                window.location.assign(`/login/directory/${provider.provider_id}/link`);
              }}
            >
              Link my identity
            </Button>
          </div>
        </>
      ) : (
        <p className="muted">This workspace has no directory sign-in enabled, so there is nothing to link.</p>
      )}
      <p className="muted">
        {administrator
          ? "An administrator's link is not removed from the console."
          : "Unlinking is an administrator action, on your page under Users."}
      </p>
    </Card>
  );
}
