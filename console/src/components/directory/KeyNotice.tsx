// SPDX-License-Identifier: AGPL-3.0-only
// One expiring key, as the agent's page and Home say it (#678): the server decides which key
// needs a notice (used, live, within seven days, not replaced by a rotation), so the two places
// cannot disagree. The agent's label is text; the link is built by the router from its id. A
// notice cannot be dismissed: it goes when the key is rotated, revoked or expires. It opens the
// agent's Connection section, where the key is rotated.

import { Link } from "@tanstack/react-router";

import type { ExpiringKey } from "../../api/types.gen";
import { Time } from "../ui/Time";
import { keyName, principalName } from "./format";

export function KeyNotice({ notice }: { notice: ExpiringKey }) {
  const agent = principalName("Agent", notice.principal_label, notice.principal_number, notice.principal_id);
  return (
    <p className="key-notice">
      <Link to="/agents/$agentId" params={{ agentId: notice.principal_id }} search={{ section: "connection" }}>
        {keyName(notice.number, notice.credential_id)} for {agent}
      </Link>{" "}
      expires <Time at={notice.expires_at} form="relative" />. It was last used{" "}
      <Time at={notice.last_used_at} form="relative" />. Rotate it, update the tool that uses it, then revoke the old
      key.
    </p>
  );
}
