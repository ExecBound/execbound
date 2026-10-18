// SPDX-License-Identifier: AGPL-3.0-only
import { lazy, Suspense, useEffect, useRef, useState } from "react";

import type { MonitorSnapshot, MonitorStory } from "../../api/types.gen";
import { useEdition } from "../../edition/context";
import { when } from "../../lib/when";
import { Button } from "../ui/Button";
import { Card } from "../ui/Card";
import { Table, Td, Th } from "../ui/Table";
import { Time } from "../ui/Time";
import { useConnectOptions, usePlacement } from "./connect";
import { STORY_ID } from "./search";
import { Snippet } from "./Snippet";
import { SourceWaiting } from "./SourceWaiting";

// Loaded the first time it opens, so the Monitoring page does not carry the form.
const AddSource = lazy(async () => ({ default: (await import("./AddSource")).AddSource }));

/**
 * The self-hosted command that registers a reporting source for one story, or null. Only an id
 * `create_source` accepts, that does not begin with `-` and leaves the fixed label `Story <id>`
 * within its 96 characters, in `--option=value` form; never the platform-supplied story name.
 */
export function reportCommand(storyId: string): string | null {
  if (!STORY_ID.test(storyId) || storyId.startsWith("-") || storyId.length > 90) return null;
  return `uv run python -m execbound.monitoring.commands create-source --credential-file local-data/admin-token.txt --label="Story ${storyId}" --story-id=${storyId} --hours 24 --output local-data/source-${storyId}.json`;
}

function ReportCommand({ command }: { command: string }) {
  const [shown, setShown] = useState(false);
  if (!shown) {
    return (
      <Button
        size="small"
        onClick={() => {
          setShown(true);
        }}
      >
        Show the command to report this story
      </Button>
    );
  }
  return (
    <div className="report-command">
      <Snippet label="Report command" value={command} />
      <p className="muted">
        The token this writes expires after 24 hours; run rotate-source before then to issue its replacement. The source is
        registered in the workspace&apos;s default space, whichever space this story&apos;s connection is in.
      </p>
      <p className="muted">
        Reporting shows this story&apos;s runs. It does not govern them; to put an action behind ExecBound, follow the Tines
        Gate recipe in integrations/tines/README.md of your ExecBound release.
      </p>
    </div>
  );
}

/** Where an expired source's token is renewed: by its Space's administrators where this reader only
 * reviews that Space, since neither Connections nor the command line lets them change it; on
 * Connections where this deployment mints, with the command line where its readers run operator
 * commands, and otherwise nowhere to send them. */
function renewWords(rotatable: boolean, operatorCommands: boolean, administered: boolean): string {
  if (!administered) return " You review its Space but do not administer it, so its administrators rotate or revoke it.";
  if (rotatable) return " Rotate its token or revoke it on Connections.";
  if (operatorCommands) return " Rotate its token with rotate-source, or revoke it on Connections.";
  return "";
}

function SourceCell({
  story,
  operatorCommands,
  rotatable,
  administered,
  onReport,
}: {
  story: MonitorStory;
  operatorCommands: boolean;
  /** Whether this deployment rotates a source's token from the console. */
  rotatable: boolean;
  /** Whether this administrator may change the named source, as its own row says. */
  administered: boolean;
  /** Where this deployment mints sources, opens Add a reporting source for this story. */
  onReport?: (storyId: string) => void;
}) {
  const gap = story.gap_opened_at !== null;
  const reportable = onReport !== undefined && gap && STORY_ID.test(story.external_id);
  const report = reportable ? (
    <div className="report-story">
      <Button
        size="small"
        onClick={() => {
          onReport(story.external_id);
        }}
      >
        Report this story
      </Button>
      <p className="muted">Report this story to see what it does. Reporting does not govern or block it.</p>
    </div>
  ) : null;
  if (story.source_id !== null) {
    // A source in a Space this reader does not see is its identifier alone: nothing about its
    // token, and nothing to do about it here.
    if (!story.source_visible) return <span className="mono">{story.source_id}</span>;
    // The gap is reassessed only when inventory is read, so whether the named source reports
    // now comes from the source itself: one minted a moment ago sits beside a gap still open. A
    // revoked connection's inventory is never read again, so its story's gap stays as it was.
    let note: string | null = null;
    if (story.source_expired) {
      note = `Its token has expired, so it does not report this story now.${renewWords(rotatable, operatorCommands, administered)}`;
    } else if (gap && story.connection_revoked) {
      note = "This source can report. This story's connection was revoked, so no inventory pass reassesses it and its gap stays open.";
    } else if (gap) {
      note = "This source can report. The gap stays open until the next inventory pass reassesses the story.";
    }
    return (
      <>
        <span className="mono">{story.source_id}</span>
        {note !== null ? <p className="muted">{note}</p> : null}
      </>
    );
  }
  const command = operatorCommands && gap ? reportCommand(story.external_id) : null;
  return (
    <>
      None registered
      {report}
      {/* The operator's command stays behind its own disclosure, secondary to the button. */}
      {command !== null ? <ReportCommand command={command} /> : null}
    </>
  );
}

/** The Inventory view: discovered stories with their coverage, and credential metadata. A
 * story named by `?story=` is marked and scrolled to (#678). */
export function Inventory({ data, story }: { data: MonitorSnapshot; story?: string }) {
  const { operatorCommands } = useEdition();
  const connect = useConnectOptions();
  // Where this deployment mints sources, and not in a Space this administrator only reviews, as
  // the server places a source now, read again once the session has moved to another Space.
  const placement = usePlacement();
  const sourcesAvailable = connect.sources === "available" && placement.reviewed === null && !placement.checking;
  // The story an administrator chose to report, held in this page's state, never the address.
  const [reporting, setReporting] = useState<string | null>(null);
  const [waiting, setWaiting] = useState<{ sourceId: string; storyId: string } | null>(null);
  const report = sourcesAvailable
    ? (storyId: string) => {
        setReporting(storyId);
      }
    : undefined;
  // The router keeps a key it did not validate, so the value is checked again here.
  const wanted = story !== undefined && STORY_ID.test(story) ? story : undefined;
  const matched = wanted !== undefined && data.stories.some((item) => item.external_id === wanted);
  // Whether this administrator may change each source the snapshot holds (`administered`). A
  // visible source is always among them, since a workspace holds at most 100.
  const administers = new Map(data.sources.map((source) => [source.source_id, source.administered]));
  const scrolled = useRef<string | undefined>(undefined);
  useEffect(() => {
    if (!matched || scrolled.current === wanted) return;
    const row = document.querySelector<HTMLElement>("tr.monitor-marked");
    if (row === null) return;
    scrolled.current = wanted;
    row.scrollIntoView({ block: "center" });
  }, [matched, wanted]);
  return (
    <>
      {reporting !== null ? (
        <Suspense fallback={null}>
          <AddSource
            storyId={reporting}
            onClose={() => {
              setReporting(null);
            }}
            onMinted={(sourceId, storyId) => {
              setWaiting({ sourceId, storyId });
            }}
          />
        </Suspense>
      ) : null}
      {/* Keyed by the source, so each new source waits its own ten minutes from its own token dialog
          closing, and given the page's own read of it once the snapshot holds it, so a heartbeat
          that read shows counts after the card's ten minutes too, as on Connections. */}
      {waiting !== null ? (
        <SourceWaiting
          key={waiting.sourceId}
          sourceId={waiting.sourceId}
          storyId={waiting.storyId}
          known={data.sources.find((source) => source.source_id === waiting.sourceId)}
        />
      ) : null}
      {wanted !== undefined && !matched ? (
        <p className="muted" role="status">
          This story is not in the discovered inventory shown here.
        </p>
      ) : null}
      <Card title="Discovered stories">
        <Table caption="Discovered stories with their coverage class, open gaps first, the oldest gap first." density="compact">
          <thead>
            <tr>
              <Th>Story</Th>
              <Th>Coverage</Th>
              <Th>Actions</Th>
              <Th>Reporting source</Th>
            </tr>
          </thead>
          <tbody>
            {data.stories.length === 0 ? (
              <tr>
                <Td colSpan={4}>No stories discovered. Run a collection with inventory enabled.</Td>
              </tr>
            ) : (
              data.stories.map((item, index) => (
                <tr
                  key={`${item.external_id} ${String(index)}`}
                  className={item.external_id === wanted ? "monitor-marked" : undefined}
                  aria-current={item.external_id === wanted ? "true" : undefined}
                >
                  <Td>
                    {item.name}
                    <small className="mono">{item.external_id}</small>
                  </Td>
                  <Td>
                    {item.coverage}
                    {item.gap_opened_at !== null ? (
                      <small>
                        Gap open since <Time at={item.gap_opened_at} />
                      </small>
                    ) : null}
                  </Td>
                  <Td>
                    {item.action_count}
                    {item.any_outbound ? (
                      <small>Outbound</small>
                    ) : item.any_unknown ? (
                      <small>Unrecognized action type</small>
                    ) : null}
                  </Td>
                  <Td>
                    <SourceCell
                      story={item}
                      operatorCommands={operatorCommands}
                      rotatable={connect.sources === "available"}
                      administered={item.source_id === null || administers.get(item.source_id) !== false}
                      onReport={report}
                    />
                  </Td>
                </tr>
              ))
            )}
          </tbody>
        </Table>
      </Card>
      <Card title="Discovered credentials">
        <Table caption="Discovered credentials; metadata only, never a value." density="compact">
          <thead>
            <tr>
              <Th>Credential</Th>
              <Th>Mode</Th>
              <Th>Expires</Th>
              <Th>State</Th>
            </tr>
          </thead>
          <tbody>
            {data.credentials.length === 0 ? (
              <tr>
                <Td colSpan={4}>No credential metadata collected.</Td>
              </tr>
            ) : (
              data.credentials.map((item) => (
                <tr key={item.external_id}>
                  <Td>
                    {item.name}
                    <small className="mono">{item.external_id}</small>
                  </Td>
                  <Td>{item.item_type ?? "Unrecorded"}</Td>
                  <Td mono>{item.source_updated_at === null ? "No expiry recorded" : when(item.source_updated_at)}</Td>
                  <Td>{item.gone_at === null ? "Present" : `Gone since ${when(item.gone_at)}`}</Td>
                </tr>
              ))
            )}
          </tbody>
        </Table>
        <p className="muted">
          Inventory is metadata only: action options, credential values, email addresses and request addresses are
          never fetched or retained. An action type the collector does not recognize is shown as unrecognized rather
          than counted as having no outbound call.
        </p>
      </Card>
    </>
  );
}
