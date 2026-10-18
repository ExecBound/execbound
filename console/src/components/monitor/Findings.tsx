// SPDX-License-Identifier: AGPL-3.0-only
import { keepPreviousData, useQuery, useQueryClient, type Query } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { useEffect, useRef, useState } from "react";

import {
  acknowledgeFindingMutation,
  acknowledgeFindingsMutation,
  readMonitorFindingOptions,
  readMonitorFindingsOptions,
  readMonitorQueryKey,
  readTenantQueryKey,
} from "../../api/@tanstack/react-query.gen";
import type { MonitorAcknowledgement, MonitorFinding, MonitorFindings } from "../../api/types.gen";
import { holdFocus } from "../../lib/focus";
import { useServerMutation } from "../../lib/mutation";
import { copyFor, refusal } from "../../lib/refusal";
import { toast } from "../../lib/toast";
import { Explain } from "../assistant/Explain";
import { PrincipalName } from "../PrincipalName";
import { Button } from "../ui/Button";
import { Chips } from "../ui/Chips";
import { EmptyState } from "../ui/EmptyState";
import { describedBy, Field } from "../ui/Field";
import { Time } from "../ui/Time";
import { FindingRow } from "./FindingRow";
import { FINDING_ID, STATES, type FindingState } from "./search";

const MONITOR_READS = new Set(["readMonitorFindings", "readMonitorFinding"]);

/** The findings reads, whichever state or finding they asked for. */
function isFindingsRead(query: Query): boolean {
  const key = query.queryKey[0] as { _id?: unknown } | undefined;
  return typeof key?._id === "string" && MONITOR_READS.has(key._id);
}

function Profile({ profile }: { profile: MonitorFindings["profile"] }) {
  return (
    <p className="muted">
      {profile === null ? (
        "Rules inactive without a detection profile: restricted-target.v1, observed-rate.v1. The built-in sensitive action set applies."
      ) : (
        <>
          Detection profile version {profile.version} active since <Time at={profile.created_at} />.
        </>
      )}
    </p>
  );
}

function Empty({ state }: { state: FindingState }) {
  if (state === "open") {
    return (
      <EmptyState title="No open findings">
        Nothing is waiting for review in this space. That does not establish that no external activity occurred;
        Connections shows quiet sources and overdue collections.
      </EmptyState>
    );
  }
  if (state === "acknowledged") return <EmptyState title="No acknowledged findings">Nothing has been acknowledged in this space.</EmptyState>;
  return (
    <EmptyState title="No findings recorded">
      Check source coverage and pending evaluations before interpreting this as a quiet period.
    </EmptyState>
  );
}

// The most findings one request acknowledges, as the server holds it.
const BULK_LIMIT = 50;
const NOTE_LIMIT = 500;
const NOTE_HINT = "Up to 500 characters. Do not paste a password, key or token.";

/** A refused acknowledgement in the note's own words where the note was the reason. */
function noteProblem(error: unknown): string {
  const { code, fields } = refusal(error);
  if (code === "INVALID_BODY" && fields.includes("note")) return "A note must not look like a password, key or token.";
  if (code === "CONFLICT") return "Someone acknowledged this finding first; your note was not saved.";
  return copyFor(error);
}

/** Nothing is shown as acknowledged until the server says so: the reads ask again. */
function useAcknowledged(): () => void {
  const queryClient = useQueryClient();
  return () => {
    void queryClient.invalidateQueries({ predicate: isFindingsRead });
    void queryClient.invalidateQueries({ queryKey: readMonitorQueryKey() });
    // The sidebar's count reads the tenant view; it follows at once.
    void queryClient.invalidateQueries({ queryKey: readTenantQueryKey() });
  };
}

function NoteField({ id, label, value, onChange }: { id: string; label: string; value: string; onChange: (value: string) => void }) {
  return (
    <Field id={id} label={label} hint={NOTE_HINT}>
      <textarea
        id={id}
        rows={2}
        maxLength={NOTE_LIMIT}
        value={value}
        aria-describedby={describedBy(id)}
        onChange={(event) => {
          onChange(event.target.value);
        }}
      />
    </Field>
  );
}

/** The note as it reads under its acknowledgement: text, line breaks kept. */
function Note({ note }: { note: string | null }) {
  return note !== null ? <p className="finding-note">Note: {note}</p> : null;
}

/** Acknowledge while the finding is open, with an optional note; who acknowledged it, when, and why, once it is not. */
function Acknowledgement({ finding }: { finding: MonitorFinding }) {
  const queryClient = useQueryClient();
  const acknowledged = useAcknowledged();
  const [note, setNote] = useState("");
  const [refused, setRefused] = useState<string | undefined>(undefined);
  const acknowledge = useServerMutation({
    ...acknowledgeFindingMutation(),
    onSuccess: (fresh) => {
      queryClient.setQueryData(readMonitorQueryKey(), fresh);
      acknowledged();
      toast("Finding acknowledged.");
    },
    onError: (error) => {
      // What was typed stays, so a refused note can be put right rather than retyped.
      setRefused(noteProblem(error));
    },
  });
  if (finding.acknowledged_at !== null) {
    return (
      <>
        <p className="muted">
          Acknowledged <Time at={finding.acknowledged_at} /> by{" "}
          {finding.acknowledged_by_ref !== null ? <PrincipalName principal={finding.acknowledged_by_ref} link /> : "an administrator"}.
        </p>
        <Note note={finding.acknowledgement_note} />
      </>
    );
  }
  return (
    <>
      <NoteField id={`note-${finding.finding_id}`} label="Note (optional)" value={note} onChange={setNote} />
      <div className="row">
        <Button
          disabled={acknowledge.isPending}
          onClick={() => {
            setRefused(undefined);
            acknowledge.mutate({ path: { finding_id: finding.finding_id }, body: note.trim() === "" ? {} : { note } });
          }}
        >
          Acknowledge finding
        </Button>
      </div>
      {refused !== undefined ? (
        <p className="fault" role="alert">
          {refused}
        </p>
      ) : null}
    </>
  );
}

type Outcome = MonitorAcknowledgement["outcome"];

interface Answered {
  results: MonitorAcknowledgement[];
  titles: Map<string, string>;
  noted: boolean;
}

const GROUPS: { outcome: Outcome; label: string }[] = [
  { outcome: "acknowledged", label: "Acknowledged now" },
  { outcome: "already_acknowledged", label: "Already acknowledged" },
  { outcome: "unavailable", label: "Not in this space, or no longer there" },
];

/** The results line: what the server did with each finding, counted. */
function sentence({ results, noted }: Answered): string {
  const count = (outcome: Outcome) => results.filter((result) => result.outcome === outcome).length;
  const already = count("already_acknowledged");
  const gone = count("unavailable");
  const parts = [`Acknowledged ${String(count("acknowledged"))}.`];
  if (already > 0) parts.push(`${String(already)} ${already === 1 ? "was" : "were"} already acknowledged.`);
  if (gone > 0) {
    parts.push(
      gone === 1
        ? "1 is not in the space you are viewing or no longer exists."
        : `${String(gone)} are not in the space you are viewing or no longer exist.`,
    );
  }
  if (noted && already > 0) parts.push("Your note was saved only on the findings acknowledged now.");
  return parts.join(" ");
}

function Results({ answered }: { answered: Answered }) {
  return (
    <div className="finding-results" role="status" aria-label="Acknowledgement results">
      <p>{sentence(answered)}</p>
      {GROUPS.map(({ outcome, label }) => {
        const titled = answered.results.filter((result) => result.outcome === outcome);
        if (titled.length === 0) return null;
        return (
          <div key={outcome}>
            <p className="muted">{label}</p>
            <ul>
              {titled.map((result) => (
                <li key={result.finding_id}>{answered.titles.get(result.finding_id) ?? "A finding no longer listed"}</li>
              ))}
            </ul>
          </div>
        );
      })}
    </div>
  );
}

/**
 * Acknowledging several open findings at once. An acknowledgement is final, so pressing
 * "Acknowledge selected" sends nothing: it asks, in place, naming the count, and only the
 * confirmation sends. Changing the selection withdraws the question. The answer is the
 * server's, one outcome per finding.
 */
function Bulk({
  open,
  selected,
  onSelect,
}: {
  open: MonitorFinding[];
  selected: string[];
  onSelect: (ids: string[]) => void;
}) {
  const acknowledged = useAcknowledged();
  const [note, setNote] = useState("");
  // The selection the question was asked about; any other selection is not confirmed.
  const [asked, setAsked] = useState<string | undefined>(undefined);
  const [answered, setAnswered] = useState<Answered | undefined>(undefined);
  const [refused, setRefused] = useState<string | undefined>(undefined);
  const returning = useRef(false);
  const confirming = selected.length > 0 && asked === selected.join(",");
  useEffect(() => {
    if (confirming) {
      document.getElementById("finding-bulk-confirm")?.focus();
    } else if (returning.current) {
      returning.current = false;
      document.getElementById("finding-bulk-ask")?.focus();
    }
  }, [confirming]);
  const acknowledge = useServerMutation({
    ...acknowledgeFindingsMutation(),
    onSuccess: (answer, variables) => {
      setAnswered({
        results: answer.results,
        titles: new Map(open.map((finding) => [finding.finding_id, finding.title])),
        noted: typeof variables.body.note === "string",
      });
      setAsked(undefined);
      onSelect([]);
      acknowledged();
    },
    onError: (error) => {
      setAsked(undefined);
      setRefused(noteProblem(error));
    },
  });
  const count = String(selected.length);
  const findingsCounted = selected.length === 1 ? "1 finding" : `${count} findings`;
  return (
    <section className="finding-bulk" aria-label="Acknowledge several findings">
      {open.length > 0 ? (
        <>
          <NoteField id="finding-bulk-note" label="Note for the selected findings (optional)" value={note} onChange={setNote} />
          <div className="row">
            <Button
              onClick={() => {
                onSelect(open.slice(0, BULK_LIMIT).map((finding) => finding.finding_id));
              }}
            >
              Select all open on this page
            </Button>
            {selected.length > 0 && !confirming ? (
              <Button
                id="finding-bulk-ask"
                variant="primary"
                onClick={() => {
                  setRefused(undefined);
                  setAsked(selected.join(","));
                }}
              >
                Acknowledge selected ({count})
              </Button>
            ) : null}
          </div>
          {confirming ? (
            <div className="finding-confirm">
              <p>Acknowledge {findingsCounted}? An acknowledgement cannot be undone.</p>
              <div className="row">
                <Button
                  id="finding-bulk-confirm"
                  variant="primary"
                  disabled={acknowledge.isPending}
                  onClick={() => {
                    acknowledge.mutate({ body: { finding_ids: selected, ...(note.trim() === "" ? {} : { note }) } });
                  }}
                >
                  Acknowledge {findingsCounted}
                </Button>
                <Button
                  disabled={acknowledge.isPending}
                  onClick={() => {
                    returning.current = true;
                    setAsked(undefined);
                  }}
                >
                  Cancel
                </Button>
              </div>
            </div>
          ) : null}
          {refused !== undefined ? (
            <p className="fault" role="alert">
              {refused}
            </p>
          ) : null}
        </>
      ) : null}
      {answered !== undefined ? <Results answered={answered} /> : null}
    </section>
  );
}

/**
 * The Findings view (#678): a queue of findings in one state, read from its own route and not
 * polled; an acknowledgement and the window regaining focus bring it up to date. `open` names
 * one finding, which opens in place, or above the list when the list does not hold it.
 */
export function Findings({ state: wanted, open: wantedOpen }: { state?: FindingState; open?: string }) {
  // The router keeps a key it did not validate, so each value is checked again here.
  const state: FindingState = wanted !== undefined && STATES.includes(wanted) ? wanted : "open";
  const open = wantedOpen !== undefined && FINDING_ID.test(wantedOpen) ? wantedOpen : undefined;
  const navigate = useNavigate({ from: "/monitor" });
  const [chosen, setChosen] = useState<string[]>([]);
  const query = useQuery({
    ...readMonitorFindingsOptions({ query: { state } }),
    // The chips stay where they are while another state loads, so the focus stays on them.
    placeholderData: keepPreviousData,
    throwOnError: (_error, failed) => failed.state.data === undefined,
  });
  const data = query.data;
  const listed = data?.findings.some((finding) => finding.finding_id === open) ?? false;
  const pinned = useQuery({
    ...readMonitorFindingOptions({ path: { finding_id: open ?? "" } }),
    enabled: open !== undefined && data !== undefined && !listed,
    retry: false,
  });
  const scrolled = useRef<string | undefined>(undefined);
  useEffect(() => {
    if (open === undefined || scrolled.current === open) return;
    const row = document.querySelector<HTMLElement>("[data-finding='open']");
    if (row === null) return;
    scrolled.current = open;
    row.scrollIntoView({ block: "start" });
  });

  const go = (search: { state?: FindingState; open?: string | undefined }) => {
    holdFocus();
    void navigate({
      search: (previous) => ({ ...previous, view: "findings" as const, ...search }),
      replace: true,
    });
  };
  const toggle = (finding: MonitorFinding) => () => {
    go({ open: finding.finding_id === open ? undefined : finding.finding_id });
  };

  if (data === undefined) {
    return (
      <p className="muted" role="status">
        Loading findings
      </p>
    );
  }
  // Only open findings this page lists can be selected; a selection outlives neither a
  // finding's acknowledgement nor a change of state.
  const openHere = data.findings.filter((finding) => finding.acknowledged_at === null);
  const selected = chosen.filter((id) => openHere.some((finding) => finding.finding_id === id));
  const select = (finding: MonitorFinding) => (checked: boolean) => {
    setChosen(checked ? [...selected, finding.finding_id] : selected.filter((id) => id !== finding.finding_id));
  };
  return (
    <>
      <Profile profile={data.profile} />
      <Chips
        label="Findings to show"
        chips={[
          { value: "open", label: `Open (${String(data.counts.open)})` },
          { value: "acknowledged", label: `Acknowledged (${String(data.counts.acknowledged)})` },
          { value: "all", label: "All" },
        ]}
        value={state}
        onChange={(next) => {
          go({ state: next, open: undefined });
        }}
      />
      {open !== undefined && !listed ? (
        <section className="finding-pinned" aria-labelledby="finding-pinned-title">
          <h2 id="finding-pinned-title" className="card-title">
            Opened from a link
          </h2>
          {pinned.data !== undefined ? (
            <ul className="finding-list">
              <FindingRow finding={pinned.data} expanded onToggle={toggle(pinned.data)}>
                <Acknowledgement finding={pinned.data} />
                <Explain kind="finding" id={pinned.data.finding_id} what="this finding" />
              </FindingRow>
            </ul>
          ) : pinned.isError ? (
            <p className="muted" role="status">
              This finding is not in the space you are viewing, or it does not exist. Switch to All spaces to look again.
            </p>
          ) : (
            <p className="muted" role="status">
              Loading the finding
            </p>
          )}
        </section>
      ) : null}
      <Bulk open={openHere} selected={selected} onSelect={setChosen} />
      {data.findings.length === 0 ? (
        <Empty state={state} />
      ) : (
        <ul className="finding-list" aria-label="Findings">
          {data.findings.map((finding) => (
            <FindingRow
              key={finding.finding_id}
              finding={finding}
              expanded={finding.finding_id === open}
              onToggle={toggle(finding)}
              selected={selected.includes(finding.finding_id)}
              onSelect={select(finding)}
            >
              <Acknowledgement finding={finding} />
              <Explain kind="finding" id={finding.finding_id} what="this finding" />
            </FindingRow>
          ))}
        </ul>
      )}
    </>
  );
}
