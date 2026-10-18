// SPDX-License-Identifier: AGPL-3.0-only
import { Link } from "@tanstack/react-router";

import { useWatchFirst } from "../monitor/connect";

/**
 * The secondary "start by watching" line (#678): below the governed path's own action, worded
 * as visibility and never as protection, and only where the reader can finish monitoring setup
 * in the console: with the edition's operator commands, or once a provider can be connected
 * from the console here, whose setup it links. Getting started's Connect step and Home's next
 * step both show it.
 */
export function WatchFirstLine() {
  const setup = useWatchFirst();
  if (setup === null) return null;
  return <p className="muted watch-first">
    Or start by watching what your Tines stories and Entra agents can already do. Monitoring shows activity; it does not block anything.{" "}
    <Link to="/monitor" search={{ setup }}>Connect a monitoring source</Link>
  </p>;
}
