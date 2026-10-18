// SPDX-License-Identifier: AGPL-3.0-only
import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";

import { createMonitorSourceMutation, readMonitorQueryKey } from "../../api/@tanstack/react-query.gen";
import { refusal } from "../../lib/refusal";
import { count } from "../../lib/when";
import { useShowOnce } from "../directory/showOnce";
import { Field } from "../ui/Field";
import { FormDialog } from "../ui/FormDialog";
import {
  HEARTBEATS,
  INTAKE_ONLY,
  LIFETIMES,
  MINT_UNCONFIRMED,
  archivedWords,
  placementWords,
  reviewedWords,
  sourceCopy,
  sourceFaults,
  usePlacement,
} from "./connect";
import { SourceTokenDialog } from "./SourceTokenDialog";

type Lifetime = (typeof LIFETIMES)[number];
type Heartbeat = (typeof HEARTBEATS)[number];

/** An expected heartbeat interval, as the form offers it. */
export function heartbeatWords(seconds: number): string {
  if (seconds === 3600) return "Every hour";
  return `Every ${count(seconds / 60, "minute")}`;
}

// What a refused field is called on this form, for the refusal line.
const FIELDS: Record<string, string> = {
  label: "Name the source in 1 to 96 characters, without anything that reads as a secret.",
  story_id: "Use the Tines story's ID: letters, digits, dots, colons, underscores or hyphens, and nothing that reads as a secret.",
};

/**
 * Add a reporting source (#678): one Tines story, the token's lifetime (30 days unless the
 * reader chooses less) and how often the story sends its heartbeat. The token comes back once,
 * through the show-once path agent keys use, so it is in no query, mutation record, address or
 * storage once its dialog closes. A refusal for a stale factor opens the step-up through the
 * shared mutation path, which sends the change again once. Opened from a story in Inventory, the
 * story's ID is filled in from component state, never from the address.
 */
export function AddSource({
  storyId,
  onClose,
  onMinted,
}: {
  storyId?: string;
  onClose: () => void;
  /** Called once the token dialog closes: the new source, and the story it reports. */
  onMinted?: (sourceId: string, storyId: string) => void;
}) {
  const queryClient = useQueryClient();
  const [label, setLabel] = useState(storyId !== undefined ? `Story ${storyId}` : "");
  const [story, setStory] = useState(storyId ?? "");
  const [lifetime, setLifetime] = useState<Lifetime>(30);
  const [heartbeat, setHeartbeat] = useState<Heartbeat>(300);
  const [touched, setTouched] = useState(false);
  const minting = useShowOnce(createMonitorSourceMutation());
  const unconfirmed = minting.error !== null && refusal(minting.error).code === "UNAVAILABLE";
  // An answer that did not arrive may still have made the source: the sources are read again.
  useEffect(() => {
    if (minting.error !== null) void queryClient.invalidateQueries({ queryKey: readMonitorQueryKey() });
  }, [minting.error, queryClient]);
  // A source left unnamed is named for its story, as the command line names one.
  const named = label.trim() === "" ? `Story ${story.trim()}` : label.trim();
  const faults = sourceFaults({ label: named, story });
  const placement = usePlacement();
  const needsSpace = placement.choose;
  const archived = placement.archived;
  // A Space this administrator only reviews takes no source from them: said before the step-up.
  const reviewed = placement.reviewed;
  const shown = touched ? faults : {};
  if (minting.secret !== null) {
    const secret = minting.secret;
    return (
      <SourceTokenDialog
        minted={secret}
        onClose={() => {
          minting.close();
          void queryClient.invalidateQueries({ queryKey: readMonitorQueryKey() });
          onMinted?.(secret.source_id, secret.story_id);
          onClose();
        }}
      />
    );
  }
  return (
    <FormDialog
      open
      onClose={onClose}
      title="Add a reporting source"
      description="A reporting source lets one Tines story send what it does, and a regular heartbeat, to ExecBound. The token is shown once."
      confirm="Create source"
      pending={minting.pending}
      error={unconfirmed ? MINT_UNCONFIRMED : minting.error !== null ? sourceCopy(minting.error, FIELDS) : undefined}
      onSubmit={() => {
        setTouched(true);
        // Nothing is placed while where it lands is read again after the session moved.
        if (Object.keys(faults).length > 0 || needsSpace || archived || reviewed !== null || placement.checking) return;
        void minting.issue({
          body: { label: named, story_id: story.trim(), lifetime_days: lifetime, heartbeat_seconds: heartbeat },
        });
      }}
    >
      <Field id="source-label" label="Source name" hint="Left blank, it is named for its story." error={shown.label}>
        <input
          id="source-label"
          value={label}
          maxLength={96}
          aria-invalid={shown.label !== undefined}
          aria-describedby={shown.label !== undefined ? "source-label-hint source-label-fault" : "source-label-hint"}
          onChange={(event) => {
            setLabel(event.target.value);
          }}
        />
      </Field>
      <Field id="source-story" label="Tines story ID" hint="The number in the story's address in Tines." error={shown.story}>
        <input
          id="source-story"
          value={story}
          maxLength={96}
          spellCheck={false}
          className="mono"
          aria-invalid={shown.story !== undefined}
          aria-describedby={shown.story !== undefined ? "source-story-hint source-story-fault" : "source-story-hint"}
          onChange={(event) => {
            setStory(event.target.value);
          }}
        />
      </Field>
      <Field id="source-lifetime" label="Token valid for">
        <select
          id="source-lifetime"
          value={lifetime}
          onChange={(event) => {
            setLifetime(Number(event.target.value) as Lifetime);
          }}
        >
          {LIFETIMES.map((days) => (
            <option key={days} value={days}>
              {count(days, "day")}
            </option>
          ))}
        </select>
      </Field>
      <Field id="source-heartbeat" label="Expected heartbeat">
        <select
          id="source-heartbeat"
          value={heartbeat}
          onChange={(event) => {
            setHeartbeat(Number(event.target.value) as Heartbeat);
          }}
        >
          {HEARTBEATS.map((seconds) => (
            <option key={seconds} value={seconds}>
              {heartbeatWords(seconds)}
            </option>
          ))}
        </select>
      </Field>
      <p>
        <strong>Placement:</strong> {placementWords(placement, "source")}
      </p>
      {touched && needsSpace ? <p role="alert">Close this and choose a Space before adding a source.</p> : null}
      {touched && archived ? <p role="alert">{archivedWords(placement, "source")}</p> : null}
      {touched && reviewed !== null ? <p role="alert">{reviewedWords(placement, "source")}</p> : null}
      <p>{INTAKE_ONLY}</p>
    </FormDialog>
  );
}
