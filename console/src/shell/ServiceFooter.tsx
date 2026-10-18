// SPDX-License-Identifier: AGPL-3.0-only
import { useService } from "../lib/session";

/**
 * The footer's Privacy, Terms and Status are the deployment's own pages (#496): each shows only
 * where it names one. Help is the console's own page and is always there. Source is where the
 * code the deployment runs can be read: the public repository, unless it says otherwise.
 */
export function ServiceFooter() {
  const service = useService();
  return (
    <footer className="service-footer" aria-label="Service information"><p>{service.operator !== null ? `© ${String(new Date().getFullYear())} ${service.operator}` : "Powered by ExecBound"} · <a href="/help">Help</a>{service.privacy_url !== null ? <> · <a href={service.privacy_url}>Privacy</a></> : null}{service.terms_url !== null ? <> · <a href={service.terms_url}>Terms</a></> : null}{service.status_url !== null ? <> · <a href={service.status_url}>Status</a></> : null}{service.source_url !== null ? <> · <a href={service.source_url}>Source</a></> : null}</p></footer>
  );
}
