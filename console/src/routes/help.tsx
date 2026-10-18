// SPDX-License-Identifier: AGPL-3.0-only
import { createFileRoute, Link } from "@tanstack/react-router";

import { Button } from "../components/ui/Button";
import { Card } from "../components/ui/Card";
import { PageHeading } from "../components/ui/PageHeading";
import { ShowSetupProgress } from "../components/welcome/SetupCardToggle";
import { useService, useSession } from "../lib/session";
import { toast } from "../lib/toast";
import { TERMS } from "../lib/terms";
import { useShellActions } from "../shell/actions";

export const Route = createFileRoute("/help")({ component: Help });

function Help() {
  const session = useSession();
  // The deployment's own contact and pages (#496): a link it names no address for is not
  // shown, and a card with nothing left is not shown at all.
  const service = useService();
  const contact = service.support_email !== null || service.status_url !== null;
  const plans = service.plans_url !== null || service.privacy_url !== null || service.security_url !== null;
  const { openShortcuts } = useShellActions();
  // The release this build carries, from the meta tag the server writes (`builtRelease`, read
  // here directly so the release check's module stays in the shell's chunk alone).
  const release = document.querySelector('meta[name="execbound-release"]')?.getAttribute("content") ?? "";
  return <><PageHeading title="Help & support" lead="Find your next step, get help, or report a problem." />
    <div className="cards"><Card title="Start here"><ol>
      <li>Connect an agent to the protected gateway. Its upstream credentials stay on the enforcement side.</li>
      <li>Review its permitted actions, trusted resources and approval rules.</li>
      <li>Send a test request, then open Activity to see the decision and result.</li>
    </ol>{session.role === "ADMIN" ? <Link to="/welcome" className="btn">Open getting started</Link> : <Link to="/activity" className="btn">Open Activity</Link>}{session.role === "ADMIN" ? <ShowSetupProgress tenant={session.tenant.id} /> : null}</Card>
    <Card title="A request is waiting or was denied"><p>Approvals shows requests you can decide. Activity explains the policy result and execution outcome. A lapsed approval needs a new request; approving never overrides a denial.</p><Link to="/approvals">Open Approvals</Link></Card>
    {service.help_url !== null ? <Card title="Documentation"><p>Guides for this deployment of ExecBound.</p><a href={service.help_url} className="btn">Open the documentation</a></Card> : null}
    <Card title="Keyboard"><p>Search, move along lists and jump to a page from the keyboard.</p><Button onClick={openShortcuts}>Keyboard shortcuts</Button></Card>
    <Card title="Sign-in and account help"><p>Manage your password, devices, authenticator, passkeys and recovery codes in My account. If you lose access, contact your workspace administrator. Never share a password, API key or recovery code with support.</p><p>Signed in with a setup credential? It expires, and cannot be used after that. Before it does, have the installation owner set up your own sign-in, a password or your organization's directory, or issue another setup credential.</p><Link to="/settings">Open My account</Link></Card>
    {contact ? <Card title="Contact support">{service.support_email !== null ? <><p>Include the page name, the approximate time, the version shown below, any request ID or error reference, and what you expected. Remove personal data and secrets from screenshots.</p><a href={`mailto:${service.support_email}?subject=ExecBound%20support`} className="btn">Email support</a></> : null}{service.status_url !== null ? <p><a href={service.status_url} className="btn">Service status and incident updates</a></p> : null}</Card> : null}
    {plans ? <Card title={service.plans_url !== null ? "Plans and privacy" : "Privacy and security"}>{service.plans_url !== null ? <><p>Need capacity, data access or account closure? Administrators can see plan usage and requests in Workspace settings. Everyone can manage optional analytics and submit a data request in My account.</p><a href={service.plans_url} className="btn">Plans and contact sales</a></> : null}{service.privacy_url !== null || service.security_url !== null ? <p>{service.privacy_url !== null ? <a href={service.privacy_url}>Privacy notice</a> : null}{service.privacy_url !== null && service.security_url !== null ? " · " : null}{service.security_url !== null ? <a href={service.security_url}>Report a security issue</a> : null}</p> : null}</Card> : null}
    <Card title="About this console">{release !== "" ? <><p>Version <code>{release.slice(0, 12)}</code></p><Button onClick={() => { void copyVersion(release); }}>Copy version</Button></> : <p>This build does not record its version.</p>}</Card>
    <Card title="Words this console uses"><dl className="glossary">{TERMS.map((entry) => <div key={entry.term}><dt>{entry.term}</dt><dd>{entry.meaning}</dd></div>)}</dl></Card></div>
  </>;
}

/** Copies the whole release, which support can match against a build. */
async function copyVersion(release: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(release);
    toast("Version copied.");
  } catch {
    toast("Copy is not available in this browser.");
  }
}
