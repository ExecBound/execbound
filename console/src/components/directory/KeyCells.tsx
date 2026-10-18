// SPDX-License-Identifier: AGPL-3.0-only
// How both key tables print an API key's expiry, last use and state (#678): relative time with
// the instant in the element's title, "Never" for a key issued to never expire, an "Expires
// soon" mark inside seven days, and "Never used" for a key that has not authenticated. The
// times are the server's, so a wrong device clock moves none of them.

import { serverNow } from "../../lib/clock";
import { Badge } from "../ui/Badge";
import { Time } from "../ui/Time";
import { expiry } from "./format";

/** How far ahead a live key is marked as expiring soon, as the server's notice counts it. */
export const SOON_MS = 7 * 24 * 60 * 60 * 1000;

interface KeyTimes {
  expires_at: string;
  state: "live" | "expired" | "revoked";
}

/** A live key that expires within seven days of the server's clock. */
export function expiresSoon(row: KeyTimes, now = serverNow()): boolean {
  if (row.state !== "live" || expiry(row.expires_at) === "Never") return false;
  return new Date(row.expires_at).getTime() - now <= SOON_MS;
}

export function KeyExpires({ row }: { row: KeyTimes }) {
  if (expiry(row.expires_at) === "Never") return <>Never</>;
  return (
    <>
      <Time at={row.expires_at} form="relative" />
      {expiresSoon(row) ? (
        <>
          {" "}
          <Badge tone="hold">Expires soon</Badge>
        </>
      ) : null}
    </>
  );
}

export function KeyLastUsed({ at }: { at: string | null | undefined }) {
  if (at === null || at === undefined || at === "") return <>Never used</>;
  return <Time at={at} form="relative" />;
}

/** The State column's words: a live key a newer key replaces says so. */
export function keyState(row: KeyTimes & { replaced?: boolean }): string {
  return row.state === "live" && row.replaced === true ? "live, replaced by a newer key" : row.state;
}
