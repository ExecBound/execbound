// SPDX-License-Identifier: AGPL-3.0-only
// Connecting monitoring from the console (#678): whether this deployment can, read once, and the
// rules the Connect Tines form and the Schedule dialog hold a value to before anything is sent.
// The server decides everything again; these only keep a form from sending what it would refuse.

import { useQuery, useQueryClient, type QueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";

import { readMonitorConnectOptions, readMonitorConnectQueryKey, readMonitorQueryKey } from "../../api/@tanstack/react-query.gen";
import type { MonitorConnection, MonitorConnectOptions, MonitorPlacement, MonitorSnapshot } from "../../api/types.gen";
import { useEdition, type Edition } from "../../edition/context";
import { copyFor, refusal } from "../../lib/refusal";
import { useSession, type SessionSummary } from "../../lib/session";
import type { MonitorProvider } from "./setup";

/** What a deployment that has not answered, or could not, offers: nothing, so the console shows
 * who connects a provider rather than a form the server would refuse. */
export const UNCONFIGURED: MonitorConnectOptions = {
  tines: "unconfigured",
  entra: "unconfigured",
  sources: "unconfigured",
  intake_url: "",
  entra_display_name: null,
  entra_client_id: null,
  last_attempt: null,
  placement: null,
};

/** Whether this deployment connects each provider from the console, and how the reader's own
 * latest Microsoft Entra consent ended. It is read once a visit and never polled: a return from
 * Microsoft is a new visit. Where a write lands (`placement`) follows the session, which another
 * tab can move to another Space, so `usePlacement` reads it again when the session has moved. */
export function useConnectOptionsQuery(enabled = true) {
  return useQuery({
    ...readMonitorConnectOptions(),
    enabled,
    refetchInterval: false,
    refetchOnWindowFocus: false,
    staleTime: Infinity,
    retry: 0,
  });
}

export function useConnectOptions(): MonitorConnectOptions {
  return useConnectOptionsQuery().data ?? UNCONFIGURED;
}

/** Where a connection or source made now lands, as a form says it before anything is sent. */
export interface Placement {
  /** The Space by name, or null where none is chosen yet. */
  name: string | null;
  archived: boolean;
  /** Several Spaces seen and none chosen: nothing is placed until one is. */
  choose: boolean;
  /** The Space's name where this administrator only reviews it, which takes nothing from them. */
  reviewed: string | null;
  /** Whether the session can choose another Space, which an administrator of one Space cannot. */
  canChoose: boolean;
  /** The session has moved to another Space since `placement` was read, and it is read again:
   * nothing is placed until it answers. */
  checking: boolean;
  /** That read failed, so where a write lands is not known. */
  unread: boolean;
}

/** Whether `placed` names another Space than the session now looks at, or none where the session
 * has one chosen, or one where it sees several and has chosen none: read while the session was
 * elsewhere, before another tab moved it. */
function behind(placed: MonitorPlacement | null, session: Pick<SessionSummary, "space" | "spaces">): boolean {
  if (session.space !== null) return placed?.space_id !== session.space.id || placed.archived !== session.space.archived;
  return placed !== null && session.spaces > 1;
}

/** The server's word on where a write lands (`placement`), which names the one Space an
 * administrator narrowed to it writes in; until it answers, the session's own view. Where the
 * session, which the shell reads again every minute and on the reader's return, now names another
 * Space than the placement, the placement is read again once, and nothing is placed until that
 * answers; an answer that still disagrees is the server's newer word, and stands. */
export function usePlacement(): Placement {
  const session = useSession();
  const read = useConnectOptionsQuery();
  // Read on every render, so the end of a read again that answered the same placement renders too.
  const fetching = read.isFetching;
  // How many answers the read has had, so a disagreement is settled only by a later one.
  const answers = useQueryClient().getQueryState(readMonitorConnectQueryKey())?.dataUpdateCount ?? 0;
  const placed = read.data?.placement;
  const disagreement =
    placed !== undefined && behind(placed, session) ? `${session.space?.id ?? ""} ${placed?.space_id ?? ""} ${String(placed?.archived)}` : null;
  // Which disagreement was seen, and how many answers the read had then: only a later answer
  // settles it.
  const [noticed, setNoticed] = useState<{ disagreement: string | null; answers: number }>({ disagreement: null, answers: 0 });
  if (noticed.disagreement !== disagreement) setNoticed({ disagreement, answers });
  const asked = useRef<string | null>(null);
  const { refetch } = read;
  useEffect(() => {
    // Settled: the same disagreement arising again later is read again.
    if (disagreement === null) {
      asked.current = null;
      return;
    }
    if (asked.current === disagreement) return;
    asked.current = disagreement;
    void refetch({ cancelRefetch: false });
  }, [disagreement, refetch]);
  const canChoose = session.spaces > 1;
  if (disagreement !== null && (noticed.disagreement !== disagreement || answers <= noticed.answers)) {
    const unread = read.isError && !fetching;
    return { name: null, archived: false, choose: false, reviewed: null, canChoose, checking: true, unread };
  }
  if (placed === null) return { name: null, archived: false, choose: true, reviewed: null, canChoose, checking: false, unread: false };
  if (placed !== undefined) {
    return {
      name: placed.name,
      archived: placed.archived,
      choose: false,
      reviewed: placed.administered ? null : placed.name,
      canChoose,
      checking: false,
      unread: false,
    };
  }
  return {
    name: session.space?.name ?? null,
    archived: session.space?.archived === true,
    choose: session.space === null && session.spaces > 1,
    reviewed: null,
    canChoose,
    checking: false,
    unread: false,
  };
}

/** The placement line a connect or source form shows. */
export function placementWords(placement: Placement, what: "connection" | "source"): string {
  if (placement.unread) return `Which Space this ${what} lands in could not be read. Close this and try again.`;
  if (placement.checking) return "Checking which Space this lands in…";
  if (placement.name !== null) return `This ${what} belongs to ${placement.name}.`;
  if (placement.choose) return "Choose a Space in the space switcher first.";
  return `This ${what} belongs to this workspace's default Space.`;
}

/** Why a Space this administrator only reviews takes nothing from them, said before the step-up,
 * and what to do where the reader can choose another. */
export function reviewedWords(placement: Placement, what: "connection" | "source"): string {
  const thing = what === "source" ? "a reporting source" : "a connection";
  return `You review ${placement.reviewed ?? "this Space"} but do not administer it, so ${thing} cannot be added there.${placement.canChoose ? " Choose a Space you administer." : ""}`;
}

/** Why an archived Space takes nothing, and what to do where the reader can do something. */
export function archivedWords(placement: Placement, what: "connection" | "source"): string {
  const named = placement.name !== null ? `${placement.name} is archived` : "This Space is archived";
  return `${named} and takes no new ${what}.${placement.canChoose ? " Choose an active Space first." : ""}`;
}

/** Microsoft's sign-in: the one address outside this console a connect flow sends the browser to,
 * and only an answer that begins with it is followed. */
export const MICROSOFT_SIGN_IN = "https://login.microsoftonline.com/";

export function isMicrosoftSignIn(address: string): boolean {
  return address.startsWith(MICROSOFT_SIGN_IN);
}

/** Leaving the console for Microsoft's sign-in, in the one place a test can watch. */
export const leave = {
  to(address: string): void {
    window.location.assign(address);
  },
};

/** What the deployment's app reads in a directory that consents to it, and nothing that writes. */
export const ENTRA_PERMISSIONS = ["AgentIdentity.Read.All", "Application.Read.All", "AuditLog.Read.All", "Directory.Read.All"] as const;

/** Where a directory administrator removes an enterprise application, in the Microsoft Entra
 * admin center: a fixed address, never one built from what a server or provider said. */
export const ENTRA_ENTERPRISE_APPS = "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/StartboardApplicationsMenuBlade/~/AppAppsPreview";

/** A connection's name, as the server admits one. */
export function labelFault(label: string): string | undefined {
  const trimmed = label.trim();
  return trimmed === "" || trimmed.length > 96 || /\p{Cc}/u.test(label) ? "Name the connection in 1 to 96 characters." : undefined;
}

/** A Tines tenant's own address, as the server admits one. */
export const TINES_URL = /^https:\/\/[A-Za-z0-9.-]{1,240}\.tines\.(com|io)$/;
const TEAM = /^[A-Za-z0-9._:-]{1,64}$/;
/** Printable ASCII with no whitespace. */
const API_KEY = /^[\x21-\x7e]{1,4096}$/;

export interface TinesForm {
  label: string;
  url: string;
  team: string;
  key: string;
}

/** Each field's fault, if it has one, in the order the form shows them. */
export function tinesFaults(form: TinesForm): Partial<Record<keyof TinesForm, string>> {
  const faults: Partial<Record<keyof TinesForm, string>> = {};
  const label = form.label.trim();
  if (label === "" || label.length > 96 || /\p{Cc}/u.test(form.label)) faults.label = "Name the connection in 1 to 96 characters.";
  if (!TINES_URL.test(form.url.trim())) faults.url = "Use your Tines tenant's address, such as https://your-tenant.tines.com.";
  if (form.team.trim() !== "" && !TEAM.test(form.team.trim())) faults.team = "A team ID is letters, digits, dots, colons, underscores or hyphens.";
  if (!API_KEY.test(form.key)) faults.key = "Paste the API key without spaces.";
  return faults;
}

export function validKey(key: string): boolean {
  return API_KEY.test(key);
}

/** The choices the Schedule dialog offers, in seconds: Tines's audit records and Entra's whole
 * directory. Tines's inventory is read daily and is not a choice. */
export const SCHEDULES = {
  tines: [300, 900, 1800, 3600],
  entra_agent_id: [3600, 10800, 21600, 43200, 86400],
} as const;

/** A probed capability's name as the pages show it. Service principal sign-ins are read from
 * Microsoft Graph's beta endpoint, so the page says so (#355). */
export function capabilityName(name: string): string {
  const words = name.replaceAll("_", " ");
  return name === "sign_ins" ? `${words} (beta)` : words;
}

/** How the connection authenticates, in words. */
export function modeWords(connection: MonitorConnection): string {
  switch (connection.credential_mode) {
    case "sealed":
      return "Key sealed for the collector";
    case "platform_app":
      return "Admin consent";
    case "key_file":
      return "Operator key file";
    case "synthetic":
      return "None: the synthetic directory exists only in ExecBound";
  }
}

/** A refusal in words, with this flow's own codes, and a form's fields named first. */
export function connectCopy(error: unknown, fields: Record<string, string> = {}): string {
  const own: Record<string, string> = {
    CONNECT_UNAVAILABLE: "Connecting from the console is not set up on this deployment.",
    CONNECTION_EXISTS: "This Space already has an active connection for that platform. Revoke it first, or use another Space.",
    CONNECTION_CAPACITY: "This workspace has as many monitoring connections as it can hold.",
    ATTEMPT_CAPACITY: "Too many connection attempts. Try again later.",
    DIRECTORY_CONNECTED: "A synthetic directory is added only to a workspace that has never connected Microsoft Entra.",
    SYNTHETIC_DIRECTORY_PRESENT:
      "This workspace holds a synthetic directory, which a workspace administrator removes before Microsoft Entra is connected in any Space.",
    SPACE_REQUIRED: "Choose a Space in the space switcher first; this connection belongs to one.",
    SPACE_ARCHIVED: "This Space is archived and takes no new connection. Choose an active Space.",
    CONFLICT: "This connection was revoked, or it changed first. Reload to see it as it is now.",
    NOT_FOUND: "This connection is not in a Space you see. Reload to see what is.",
    FORBIDDEN: "This Space is one you review, not one you administer, so its monitoring connections are not yours to change.",
  };
  const { code, fields: faults } = refusal(error);
  if (faults.some((fault) => fields[fault] !== undefined)) return copyFor(error, fields);
  return own[code] ?? copyFor(error, fields);
}

/** The snapshot as the server now holds one connection: its answer replaces the row, and the
 * whole snapshot is read again behind it. Nothing is shown before the server answered. */
export function answered(queryClient: QueryClient, connection: MonitorConnection): void {
  queryClient.setQueryData<MonitorSnapshot>(readMonitorQueryKey(), (snapshot) =>
    snapshot === undefined
      ? snapshot
      : {
          ...snapshot,
          connections: snapshot.connections.map((row) => (row.connection_id === connection.connection_id ? connection : row)),
        },
  );
  void queryClient.invalidateQueries({ queryKey: readMonitorQueryKey() });
}

/** How long a reporting source's token lives, in days: 30 by default, and never longer (#678). */
export const LIFETIMES = [1, 7, 30] as const;
/** How often a reporting story sends its heartbeat, in seconds: 5 minutes by default (#678). Never
 * every minute: the health pass calls a source that never reported silent twice its interval
 * after it is added, which for a minute is before most stories are built. */
export const HEARTBEATS = [300, 900, 3600] as const;
/** How long a rotated source's previous token keeps reporting, in minutes. */
export const GRACES = [0, 10, 30, 60] as const;
/** The events a source keeps over its whole life, the server's limit: intake refuses its story's
 * further events once it has kept this many, and rotating its token does not reset the count, so
 * the story is added again beside it. `test_mc15_the_console_holds_the_servers_source_bounds`
 * holds it to the store's own number. */
export const SOURCE_EVENTS = 10_000;

/** What a source token can do, said above every button that mints one (#678). */
export const INTAKE_ONLY =
  "This token authorizes intake only. It lets one Tines story send events about itself to ExecBound. It cannot run actions, approve requests or read anything from ExecBound.";

/** A Tines story's ID, as the server admits one. */
const STORY = /^[A-Za-z0-9._:-]{1,96}$/;

export interface SourceForm {
  label: string;
  story: string;
}

/** Each field's fault, if it has one, in the order the form shows them. */
export function sourceFaults(form: SourceForm): Partial<Record<keyof SourceForm, string>> {
  const faults: Partial<Record<keyof SourceForm, string>> = {};
  const label = form.label.trim();
  if (label === "" || label.length > 96 || /\p{Cc}/u.test(form.label)) faults.label = "Name the source in 1 to 96 characters.";
  if (!STORY.test(form.story.trim())) faults.story = "A story ID is letters, digits, dots, colons, underscores or hyphens, up to 96.";
  return faults;
}

/** A source refusal in words, with this flow's own codes, and a form's fields named first. */
export function sourceCopy(error: unknown, fields: Record<string, string> = {}): string {
  const own: Record<string, string> = {
    CONNECT_UNAVAILABLE: "Adding a reporting source from the console is not set up on this deployment.",
    // Revoked sources count toward the limit and are kept, so no advice to revoke one.
    SOURCE_CAPACITY:
      "This workspace has as many reporting sources as it can hold: 100, revoked ones included, so revoking one does not make room.",
    // A source that has kept all its events never refuses its story's next one, so the source
    // found here still takes events, and no advice to revoke it: revoking is final and stops
    // its heartbeats, and a full workspace refuses the story's next source.
    SOURCE_EXISTS: "This Space already has a reporting source for that story. Rotate its token on Connections to issue a new one.",
    SPACE_REQUIRED: "Choose a Space in the space switcher first; this source belongs to one.",
    SPACE_ARCHIVED: "This Space is archived and takes no new source. Choose an active Space.",
    CONFLICT: "This source was revoked, or it changed first. Reload to see it as it is now.",
    FORBIDDEN: "This Space is one you review, not one you administer, so its reporting sources are not yours to change.",
    NOT_FOUND: "This source is not in a Space you see. Reload to see what is.",
  };
  const { code, fields: faults } = refusal(error);
  if (faults.some((fault) => fields[fault] !== undefined)) return copyFor(error, fields);
  return own[code] ?? copyFor(error, fields);
}

/** What a mint whose answer did not arrive may have done: the source may exist, so the form never
 * says nothing was changed, and a story's one source per Space that can still take its events
 * keeps a retry from adding another. */
export const MINT_UNCONFIRMED =
  "ExecBound did not confirm the source, so it may have been created. Look for it on Connections before trying again; a Space holds one source for a story that can still take its events, so trying again cannot add another.";

/** The same for a rotation whose answer did not arrive: a new token may exist that nobody holds. */
export const ROTATION_UNCONFIRMED =
  "ExecBound did not confirm the rotation, so a new token may have been issued and the previous one may stop at the end of the grace you chose. If the source's expiry on Connections has changed, rotate again to get a token you hold.";

/** The same for a revocation: the source may already refuse every token. */
export const REVOCATION_UNCONFIRMED =
  "ExecBound did not confirm the revocation, so it may have taken effect. Check the source on Connections before trying again.";

/** The host a story's reporting credential is restricted to: the intake address's own. */
export function intakeHost(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}

/** A heartbeat body for one story, as the intake takes it: the story's ID filled in, and the
 * two values that change on every heartbeat left for the story to fill. Never a token. */
export function heartbeatBody(storyId: string): string {
  return JSON.stringify(
    {
      version: 1,
      event_id: "<a new ID for each heartbeat>",
      story_id: storyId,
      occurred_at: "<the time it is sent, such as 2026-10-12T18:00:00Z>",
      kind: "heartbeat",
    },
    null,
    2,
  );
}

/**
 * Whether Getting started and Home offer watching first, and which provider's setup the offer
 * links (#678). Where the edition's readers run operator commands, the guided setup works today,
 * so it offers Tines as it always has. Elsewhere it waits until the deployment says a provider
 * can be connected from the console, so it never leads an administrator to a setup that ends in
 * "ask your service operator": Tines where it is available, Microsoft Entra where only it is.
 */
export function watchFirstSetup(
  edition: Pick<Edition, "watchFirst" | "operatorCommands">,
  connect: MonitorConnectOptions,
): MonitorProvider | null {
  if (!edition.watchFirst) return null;
  if (edition.operatorCommands || connect.tines === "available") return "tines";
  if (connect.entra === "available") return "entra_agent_id";
  return null;
}

/** `watchFirstSetup` for this reader. Only an administrator's console can connect a provider,
 * and only where the edition's own commands do not already settle it is anything read. */
export function useWatchFirst(): MonitorProvider | null {
  const edition = useEdition();
  const { role } = useSession();
  const asks = edition.watchFirst && !edition.operatorCommands && role === "ADMIN";
  const read = useConnectOptionsQuery(asks);
  return watchFirstSetup(edition, asks ? (read.data ?? UNCONFIGURED) : UNCONFIGURED);
}
