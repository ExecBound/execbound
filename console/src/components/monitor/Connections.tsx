// SPDX-License-Identifier: AGPL-3.0-only
import { lazy, Suspense, useEffect, useRef, useState } from "react";

import type { MonitorConnectAttempt, MonitorConnection, MonitorSnapshot, MonitorSource } from "../../api/types.gen";
import { useEdition } from "../../edition/context";
import { serverNow } from "../../lib/clock";
import { PrincipalName } from "../PrincipalName";
import { count, when } from "../../lib/when";
import { Badge, type Tone } from "../ui/Badge";
import { Button } from "../ui/Button";
import { Card } from "../ui/Card";
import { Definition, Definitions } from "../ui/Definitions";
import { EmptyState } from "../ui/EmptyState";
import { Table, Td, Th } from "../ui/Table";
import { Time } from "../ui/Time";
import { modeWords, UNCONFIGURED, useConnectOptionsQuery } from "./connect";
import { ConnectionActions, type PlatformApp } from "./ConnectionActions";
import { MonitorSetup } from "./MonitorSetup";
import { isQuietConnection, isQuietSource } from "./quiet";
import { ServiceOperatorCopy } from "./ServiceOperatorCopy";
import type { MonitorProvider } from "./setup";
import { SourceActions } from "./SourceActions";
import { SourceWaiting } from "./SourceWaiting";

// Loaded the first time each opens, so the Monitoring page does not carry the forms.
const ConnectTines = lazy(async () => ({ default: (await import("./ConnectTines")).ConnectTines }));
const ConnectEntra = lazy(async () => ({ default: (await import("./ConnectEntra")).ConnectEntra }));
const AddSource = lazy(async () => ({ default: (await import("./AddSource")).AddSource }));

/** What is open over the view: the guided setup, from the card or the address (`direct`), or
 * a provider's connect dialog. */
type Opening =
  | { kind: "guide"; provider?: MonitorProvider; connectionId?: string; direct?: boolean }
  | { kind: "tines" }
  | { kind: "entra" }
  | { kind: "source" }
  | null;

/** What the page says once Microsoft sends the browser back: from the server's record of the
 * reader's own latest attempt, never from the address, which only says a return happened. */
function returnWords(attempt: MonitorConnectAttempt, displayName: string | null): string {
  if (attempt.outcome === "consented") return "Microsoft Entra is connected. The first collection runs within five minutes.";
  if (!attempt.refused_after_consent) return "The connection was not made, and nothing was created. Start again from Connect Microsoft Entra.";
  const app = displayName !== null ? `the ${displayName} enterprise application` : "this deployment's enterprise application";
  return `Nothing was created in ExecBound. If you approved access in Microsoft, remove ${app} from your directory to withdraw it.`;
}

function healthWord(state: string): string {
  const lower = state.replaceAll("_", " ").toLowerCase();
  return lower.charAt(0).toUpperCase() + lower.slice(1);
}

function Figures({ data }: { data: MonitorSnapshot }) {
  const figures: [string, number][] = [
    ["Registered sources shown", data.sources.length],
    ["Recent observations shown", data.observations.length],
    ["Recent findings shown", data.findings.length],
    ["Discovered stories shown", data.stories.length],
  ];
  return (
    <dl className="figures" aria-label="What is shown">
      {figures.map(([label, value]) => (
        <div key={label} className="figure">
          <dt className="figure-label">{label}</dt>
          <dd className="figure-value">{value}</dd>
        </div>
      ))}
    </dl>
  );
}

// A connection the collector opens itself is overdue at twice its own interval or a day, whichever is shorter.
const OVERDUE_SEALED =
  "No collection run has been recorded within twice this connection's interval, so what is shown here may be out of date. A collector that stopped and a key it can no longer open both look like this.";
const OVERDUE_CONSENTED =
  "No collection run has been recorded within twice this connection's interval, or a day if that is sooner, so what is shown here may be out of date. A collector that stopped and a consent that was withdrawn both look like this.";

const OVERDUE = {
  operator:
    "No collection run has been recorded for a day, so what is shown here may be out of date. A schedule that stopped and a collector that can no longer sign in both look like this.",
  service:
    "No collection run has been recorded for a day, so what is shown here may be out of date. This service collects a connection on its schedule only where its collector holds the connection's key file; otherwise collection runs when an operator runs it.",
};

/** A whole number of hours, minutes or seconds, as the schedule states it. */
function span(seconds: number): string {
  if (seconds % 3600 === 0) return count(seconds / 3600, "hour");
  if (seconds % 60 === 0) return count(seconds / 60, "minute");
  return count(seconds, "second");
}

/** What the scheduled collector reads, and how often (#678): Tines's audit records on their own
 * interval and its inventory daily, or Entra's whole directory on its one interval. */
function scheduleWords(connection: MonitorConnection): string {
  if (connection.activity_interval_seconds === null) return `Every ${span(connection.collect_interval_seconds)}`;
  return `Audit records every ${span(connection.activity_interval_seconds)}, inventory daily`;
}

/** A stable order: quiet first, then whatever else needs attention, then the rest, each in the server's order. */
function ordered<T>(items: readonly T[], rank: (item: T) => number): T[] {
  return items
    .map((item, index) => ({ item, index, rank: rank(item) }))
    .sort((a, b) => a.rank - b.rank || a.index - b.index)
    .map(({ item }) => item);
}

const connectionRank = (connection: MonitorConnection) => (isQuietConnection(connection) ? 0 : connection.reporting ? 2 : 1);
const sourceRank = (source: MonitorSource) => (isQuietSource(source) ? 0 : source.coverage === "Reporting" ? 2 : 1);

/** The Connections view: each collection connection, the figures, then each reporting source.
 * Quiet items come first (#678); `focus="quiet"` scrolls to the first and marks it. */
export function Connections({
  data,
  focus,
  setup: opening,
  onSetupClosed,
  connect: arrived,
  onConnectRead,
}: {
  data: MonitorSnapshot;
  focus?: "quiet";
  /** A provider named by the address (`?setup=`, #678): its setup dialog opens on arrival. */
  setup?: MonitorProvider;
  onSetupClosed?: () => void;
  /** A return from Microsoft (`?connect=`): what it means is read from the server. */
  connect?: "done" | "refused";
  /** Called once the return has been read, to take it out of the address. */
  onConnectRead?: () => void;
}) {
  const [setup, setSetup] = useState<Opening>(() =>
    opening === undefined ? null : { kind: "guide", provider: opening, direct: true },
  );
  const { operatorCommands } = useEdition();
  const options = useConnectOptionsQuery();
  const connect = options.data ?? UNCONFIGURED;
  const tinesAvailable = connect.tines === "available";
  const entraAvailable = connect.entra === "available";
  // Console minting is live exactly where console connect is (#678).
  const sourcesAvailable = connect.sources === "available";
  // The source just minted here, whose first heartbeat its card waits for.
  const [waiting, setWaiting] = useState<{ sourceId: string; storyId: string } | null>(null);
  const platformApp: PlatformApp | null =
    entraAvailable && connect.entra_display_name !== null && connect.entra_client_id !== null
      ? { displayName: connect.entra_display_name, clientId: connect.entra_client_id }
      : null;
  // A provider's connect dialog where this deployment connects it from here: asked for by its
  // button, or by the address naming it, which otherwise opens the guided setup as before.
  const named = (provider: MonitorProvider) =>
    setup !== null && setup.kind === "guide" && setup.direct === true && setup.provider === provider && setup.connectionId === undefined;
  const connectingTines = setup !== null && (setup.kind === "tines" || (tinesAvailable && named("tines")));
  const connectingEntra = setup !== null && platformApp !== null && (setup.kind === "entra" || named("entra_agent_id"));
  const closeSetup = () => {
    setSetup(null);
    onSetupClosed?.();
  };
  // The return from Microsoft, read once the server's record of it has been read, and kept on
  // the page after the address no longer says it. With no record, as a crafted link has, the
  // page says nothing.
  const [returning] = useState(arrived);
  const [read, setRead] = useState(false);
  if (returning !== undefined && !read && !options.isPending) {
    // Once, as the record arrives: a consent that made a connection opens its verification.
    setRead(true);
    const attempt = options.data?.last_attempt ?? null;
    if (attempt !== null && attempt.outcome === "consented" && attempt.connection_id !== null) {
      setSetup({ kind: "guide", provider: "entra_agent_id", connectionId: attempt.connection_id });
    }
  }
  const returned: MonitorConnectAttempt | null = read ? (options.data?.last_attempt ?? null) : null;
  useEffect(() => {
    if (read) onConnectRead?.();
  }, [read, onConnectRead]);
  const connections = ordered(data.connections, connectionRank);
  const sources = ordered(data.sources, sourceRank);
  // The one card the count included and the link was built for, if one is still quiet.
  const marked =
    focus !== "quiet"
      ? undefined
      : (connections.find(isQuietConnection)?.connection_id ?? sources.find(isQuietSource)?.source_id);
  const scrolled = useRef(false);
  useEffect(() => {
    if (marked === undefined || scrolled.current) return;
    const card = document.querySelector<HTMLElement>(".monitor-marked");
    if (card === null) return;
    scrolled.current = true;
    card.scrollIntoView({ block: "start" });
  }, [marked]);
  const mark = (id: string) => (id === marked ? { className: "monitor-marked", "aria-current": "true" as const } : {});
  return (
    <>
      <Card
        title="Connect monitoring"
        aside={
          <div className="monitor-actions">
            {tinesAvailable ? (
              <Button variant="primary" onClick={() => { setSetup({ kind: "tines" }); }}>
                Connect Tines
              </Button>
            ) : null}
            {platformApp !== null ? (
              <Button variant={tinesAvailable ? "default" : "primary"} onClick={() => { setSetup({ kind: "entra" }); }}>
                Connect Microsoft Entra
              </Button>
            ) : null}
            {sourcesAvailable ? (
              <Button onClick={() => { setSetup({ kind: "source" }); }}>
                Add a reporting source
              </Button>
            ) : null}
            <Button variant={tinesAvailable || platformApp !== null ? "default" : "primary"} onClick={() => { setSetup({ kind: "guide" }); }}>
              Connect a source
            </Button>
          </div>
        }
      >
        <p>
          Collect Tines workflow metadata or Microsoft Entra identities and grants.{" "}
          {tinesAvailable
            ? "Connect Tines with a read-only API key, sealed for ExecBound's collector, which collects on a schedule. Guided setup covers every provider and verifies the first sync."
            : operatorCommands
              ? "Guided setup includes permissions, operator commands and verification of the first sync."
              : "Guided setup says who connects a provider here and verifies the first sync."}
        </p>
        {platformApp !== null ? (
          <p>Connect Microsoft Entra by a directory administrator&apos;s consent to {platformApp.displayName}, which reads it on a schedule.</p>
        ) : null}
        <p className="muted">Monitoring is visibility. It does not enforce action policy or prevent an external connector from acting.</p>
        {returned !== null ? (
          <p className="monitor-note" role="status">
            {returnWords(returned, connect.entra_display_name)}
          </p>
        ) : null}
      </Card>
      {setup !== null && setup.kind === "source" && sourcesAvailable ? (
        <Suspense fallback={null}>
          <AddSource
            onClose={closeSetup}
            onMinted={(sourceId, storyId) => {
              setWaiting({ sourceId, storyId });
            }}
          />
        </Suspense>
      ) : connectingEntra ? (
        <Suspense fallback={null}>
          <ConnectEntra displayName={platformApp.displayName} onClose={closeSetup} />
        </Suspense>
      ) : connectingTines ? (
        <Suspense fallback={null}>
          <ConnectTines
            onClose={closeSetup}
            onConnected={(connectionId) => {
              setSetup({ kind: "guide", provider: "tines", connectionId });
            }}
          />
        </Suspense>
      ) : setup !== null && setup.kind === "guide" ? (
        <MonitorSetup
          provider={setup.provider}
          connectionId={setup.connectionId}
          onConnectTines={tinesAvailable ? () => { setSetup({ kind: "tines" }); } : undefined}
          onConnectEntra={platformApp !== null ? () => { setSetup({ kind: "entra" }); } : undefined}
          onClose={closeSetup}
        />
      ) : null}
      {focus === "quiet" && marked === undefined ? (
        <p className="muted" role="status">
          Nothing is quiet now.
        </p>
      ) : null}
      {data.connections.length === 0 ? (
        <EmptyState title="No collection connection registered">
          {operatorCommands ? (
            <>
              Register a read-only collection connection to discover stories, actions and credential metadata and to
              collect audit records. Without one, only explicitly instrumented stories report.
            </>
          ) : (
            <>
              <p>
                A read-only collection connection discovers stories, actions and credential metadata and collects audit
                records. Without one, only explicitly instrumented stories report.
              </p>
              <ServiceOperatorCopy subject="monitoring providers" />
            </>
          )}
        </EmptyState>
      ) : (
        connections.map((connection) => {
          // The allow tone exactly when the evidence shows collection running and complete,
          // recently: the verifier's own rule, so the two never disagree.
          const tone: Tone = connection.reporting ? "allow" : "hold";
          const overdue = connection.overdue_since !== null;
          const word = overdue && connection.health_state === "COLLECTING" ? "Collection overdue" : healthWord(connection.health_state);
          const entra = connection.base_url === "https://graph.microsoft.com";
          const capabilities = Object.entries(connection.capabilities).sort(([a], [b]) => a.localeCompare(b));
          return (
            <Card
              key={connection.connection_id}
              title={connection.label}
              aside={<Badge tone={tone}>{word}</Badge>}
              {...mark(connection.connection_id)}
            >
              <Definitions aria-label={`Connection ${connection.label}`}>
                <Definition term="Connection ID" mono>{connection.connection_id}</Definition>
                <Definition term="Platform origin" mono>
                  {connection.base_url}
                </Definition>
                <Definition term="Collection scope">{entra ? "Registered Microsoft Entra directory" : connection.team_id ?? "Every team the key can read"}</Definition>
                <Definition term="Credential">{modeWords(connection)}</Definition>
                <Definition term="Audit cursor" mono>
                  {connection.audit_cursor === null ? "Nothing collected yet" : when(connection.audit_cursor)}
                </Definition>
                <Definition term="Last run" mono>
                  {connection.last_run_at === null ? "Never" : when(connection.last_run_at)}
                  {connection.last_outcome !== null ? ` (${connection.last_outcome})` : ""}
                </Definition>
                <Definition term="Last inventory sync" mono>
                  {connection.last_sync_at === null ? "Never" : when(connection.last_sync_at)}
                </Definition>
                {connection.retry_after_seconds !== null ? (
                  <Definition term="Platform asked to retry after">
                    {count(connection.retry_after_seconds, "second")}
                  </Definition>
                ) : null}
                {connection.revoked_at !== null ? (
                  <Definition term="Revoked" mono>
                    {when(connection.revoked_at)}
                  </Definition>
                ) : null}
                {connection.consented_at !== null ? (
                  <Definition term="Consent recorded">
                    <Time at={connection.consented_at} /> by{" "}
                    {connection.consented_by !== null ? <PrincipalName principal={connection.consented_by} kind="ADMIN" /> : "an administrator"}
                  </Definition>
                ) : null}
                {connection.overdue_since !== null ? (
                  <Definition term="Overdue since">
                    <Time at={connection.overdue_since} />
                  </Definition>
                ) : null}
                {connection.next_due_at !== null ? (
                  <Definition term="Schedule">{scheduleWords(connection)}</Definition>
                ) : null}
              </Definitions>
              {connection.collecting ? (
                <p className="monitor-note">Collecting now.</p>
              ) : connection.next_due_at !== null ? (
                <p className="muted">
                  {connection.credential_mode !== "key_file"
                    ? "The collector reads it on this schedule."
                    : "Collected on this schedule where the collector holds this connection's key file."}{" "}
                  {/* A due time already passed is one no collector has taken up yet. */}
                  {Date.parse(connection.next_due_at) <= serverNow() ? "Due since" : "Next due"}{" "}
                  <Time at={connection.next_due_at} />.
                </p>
              ) : null}
              {overdue ? (
                <p className="monitor-note">
                  {connection.credential_mode === "sealed"
                    ? OVERDUE_SEALED
                    : connection.credential_mode === "platform_app"
                      ? OVERDUE_CONSENTED
                      : operatorCommands
                        ? OVERDUE.operator
                        : OVERDUE.service}
                </p>
              ) : connection.health_state === "COLLECTING" && !connection.reporting ? (
                <p className="monitor-note">
                  The last run did not complete, or a permission the collector needs is not available. The setup&apos;s
                  Verify step says which.
                </p>
              ) : null}
              <Table
                caption={`Collection capabilities of ${connection.label} as classified by the last probe.`}
                density="compact"
              >
                <thead>
                  <tr>
                    <Th>Capability</Th>
                    <Th>Classification</Th>
                    <Th>Probed</Th>
                  </tr>
                </thead>
                <tbody>
                  {capabilities.length === 0 ? (
                    <tr>
                      <Td colSpan={3}>Not probed yet.</Td>
                    </tr>
                  ) : (
                    capabilities.map(([name, value]) => (
                      <tr key={name}>
                        <Td>{name.replaceAll("_", " ")}</Td>
                        <Td>{value.state}</Td>
                        <Td mono>{value.at === null || value.at === undefined ? "" : when(value.at)}</Td>
                      </tr>
                    ))
                  )}
                </tbody>
              </Table>
              {connection.last_error_code !== null ? (
                <p className="muted monitor-note">
                  Last collection refusal: <span className="mono">{connection.last_error_code}</span>. Coverage may be
                  incomplete.
                </p>
              ) : null}
              <p className="muted">
                {entra ? "Collected directory identities and grants infer authority. Where the audit log capability is available, the directory's own log shows which mapped identity actions an application took, by object id; neither shows that an external route is governed. Azure RBAC and group-mediated roles are not covered." : "Collected from the platform's audit and inventory APIs with a read-only key. An ordinary action's effect is not an audit record, so this does not establish what a connector did. Audit and AI-audit capabilities remain fixture-tested."}
              </p>
              <ConnectionActions connection={connection} connectAvailable={tinesAvailable} platformApp={platformApp} />
              <Button onClick={() => { setSetup({ kind: "guide", provider: entra ? "entra_agent_id" : "tines", connectionId: connection.connection_id }); }}>Verify connection</Button>
            </Card>
          );
        })
      )}
      {/* Four zeros between two empty boxes say nothing; the figures follow a first source (#678). */}
      {data.connections.length > 0 || data.sources.length > 0 ? <Figures data={data} /> : null}
      {/* A source minted a moment ago that the snapshot has not caught up with yet. */}
      {waiting !== null && !data.sources.some((source) => source.source_id === waiting.sourceId) ? (
        <SourceWaiting key={waiting.sourceId} sourceId={waiting.sourceId} storyId={waiting.storyId} />
      ) : null}
      {data.sources.length === 0 ? (
        <EmptyState title="No sources registered">
          Provision a scoped reporting source to receive selected Tines story events. Your vendor connectors stay in
          Tines.
        </EmptyState>
      ) : (
        sources.map((source) => (
          <Card
            key={source.source_id}
            title={source.label}
            aside={<Badge tone={source.coverage === "Reporting" ? "allow" : "hold"}>{source.coverage}</Badge>}
            {...mark(source.source_id)}
          >
            <Definitions aria-label={`Source ${source.label}`}>
              <Definition term="Instrumented story" mono>
                {source.story_id}
              </Definition>
              <Definition term="Last event received" mono>
                {source.last_event_at === null ? "No events received" : when(source.last_event_at)}
              </Definition>
              <Definition term="Last heartbeat" mono>
                {source.last_heartbeat_at === null ? "No heartbeat received" : when(source.last_heartbeat_at)}
              </Definition>
              <Definition term="Expected heartbeat">Every {count(source.heartbeat_seconds, "second")}</Definition>
              <Definition term="Health">
                {healthWord(source.health_state)}
                {source.health_changed_at !== null ? (
                  <>
                    {" "}
                    since <span className="mono">{when(source.health_changed_at)}</span>
                  </>
                ) : null}
              </Definition>
              <Definition term="Source credential expiry" mono>
                {when(source.expires_at)}
              </Definition>
              {source.previous_valid_until !== null ? (
                <Definition term="Previous credential accepted until" mono>
                  {when(source.previous_valid_until)}
                </Definition>
              ) : null}
              {source.revoked_at !== null ? (
                <Definition term="Revoked" mono>
                  {when(source.revoked_at)}
                </Definition>
              ) : null}
            </Definitions>
            {source.last_refusal_code !== null ? (
              <p className="muted monitor-note">
                Recent intake refusal: <span className="mono">{source.last_refusal_code}</span>. Coverage may be
                incomplete.
              </p>
            ) : null}
            {waiting !== null && waiting.sourceId === source.source_id ? (
              <SourceWaiting sourceId={source.source_id} storyId={source.story_id} known={source} />
            ) : null}
            <p className="muted">
              Only this explicitly instrumented story is covered. Other connectors and unreported calls may exist.
              Tenant-wide discovery is not enabled.
            </p>
            <SourceActions source={source} mintAvailable={sourcesAvailable} />
          </Card>
        ))
      )}
    </>
  );
}
