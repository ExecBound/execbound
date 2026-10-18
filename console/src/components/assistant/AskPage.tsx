// SPDX-License-Identifier: AGPL-3.0-only
import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import { useId, useState } from "react";

import { listAssistantTurnsOptions } from "../../api/@tanstack/react-query.gen";
import type { TurnView } from "../../api/types.gen";
import { turnTitle, useAssistant } from "../../lib/assistant";
import { copyFor } from "../../lib/refusal";
import { useSession } from "../../lib/session";
import { when } from "../../lib/when";
import { NotFound } from "../NotFound";
import { Badge } from "../ui/Badge";
import { Button } from "../ui/Button";
import { Card } from "../ui/Card";
import { EmptyState } from "../ui/EmptyState";
import { describedBy, Field } from "../ui/Field";
import { PageHeading } from "../ui/PageHeading";
import { ASSISTANT_FIELDS, useAsk } from "./ask";

const QUESTION_LIMIT = 1000;

/**
 * Ask (#330): a question box and the person's own recent turns.
 *
 * The page says what the assistant is before it invites a question, because what it is, is
 * the point: it reads the tenant's records with the asking person's own permissions, changes
 * nothing, and never says what to decide. The turns below are that person's alone; an
 * administrator reading this page sees their own and nobody else's.
 *
 * Whether the tenant turned it on is the administrator's route to read, so an approver is not
 * told here: they ask, and a tenant with the switch off refuses with `ASSISTANT_OFF`, which
 * the box shows. An administrator is told before they type, with the way to change it.
 */
export function AskPage({ initial = "" }: { initial?: string }) {
  const assistant = useAssistant();
  const session = useSession();
  const navigate = useNavigate();
  const id = useId();
  const [question, setQuestion] = useState(initial);
  const [missing, setMissing] = useState(false);
  const ask = useAsk((turn) => {
    setQuestion("");
    void navigate({ to: "/ask/$turnId", params: { turnId: turn.turn_id } });
  });
  const turns = useQuery({ ...listAssistantTurnsOptions(), enabled: assistant.exists });

  // Absent means the feature does not exist (#330): the address names no page at all, which
  // is a different answer from "the tenant has not turned it on" below.
  if (!assistant.exists) return <NotFound />;
  const off = assistant.known && !assistant.enabled;

  return (
    <>
      <PageHeading
        title="Ask"
        lead="Ask about this tenant's records and get an answer in plain words with the records it rests on. The assistant reads exactly what you can read, changes nothing, and never says whether to approve or refuse."
      />
      {off ? (
        <Off admin={session.role === "ADMIN"} />
      ) : (
        <Card title="Your question">
          <form
            onSubmit={(event) => {
              event.preventDefault();
              const text = question.trim();
              setMissing(text.length === 0);
              if (text.length === 0) return;
              ask.mutate({ body: { question: text } });
            }}
          >
            <Field
              id={`${id}-question`}
              label="What would you like to know?"
              hint={`Up to ${String(QUESTION_LIMIT)} characters. Your questions and their answers are yours: no other person of this tenant can read them, and they are erased thirty days after the answer.`}
              error={
                missing
                  ? ASSISTANT_FIELDS.question
                  : ask.isError
                    ? copyFor(ask.error, ASSISTANT_FIELDS)
                    : undefined
              }
            >
              <textarea
                id={`${id}-question`}
                name="question"
                rows={3}
                maxLength={QUESTION_LIMIT}
                required
                value={question}
                aria-describedby={describedBy(`${id}-question`)}
                aria-invalid={missing ? true : undefined}
                onChange={(event) => {
                  setQuestion(event.target.value);
                  setMissing(false);
                }}
              />
            </Field>
            <div className="row">
              <Button type="submit" variant="primary" disabled={ask.isPending}>
                {ask.isPending ? "Asking…" : "Ask"}
              </Button>
              {assistant.settings !== undefined ? (
                <span className="muted">
                  Answered by {assistant.settings.model}, up to{" "}
                  {assistant.settings.person_hourly_turns} questions an hour.
                </span>
              ) : null}
            </div>
          </form>
        </Card>
      )}
      <Recent turns={turns.data?.turns ?? []} loading={turns.isPending} />
      {assistant.settings !== undefined ? (
        <p className="muted retention">{assistant.settings.provider_retention}</p>
      ) : null}
    </>
  );
}

function Off({ admin }: { admin: boolean }) {
  return (
    <Card title="The assistant is not turned on for this tenant">
      <p className="muted">
        Nothing is sent to a model provider while it is off, and no question can be asked.
      </p>
      {admin ? (
        <p>
          An administrator turns it on in <Link to="/tenant">Workspace settings</Link>, with a reason
          that is recorded, after reading what the provider keeps.
        </p>
      ) : (
        <p className="muted">An administrator of this tenant can turn it on.</p>
      )}
    </Card>
  );
}

const TONES: Record<string, "allow" | "hold" | "stale"> = {
  COMPLETED: "allow",
  RUNNING: "hold",
  FAILED: "stale",
};

/** The server states a turn's state as text; a state this build does not know reads as stale. */
function tone(state: string): "allow" | "hold" | "stale" {
  return TONES[state] ?? "stale";
}

function Recent({ turns, loading }: { turns: readonly TurnView[]; loading: boolean }) {
  return (
    <Card title="Your recent questions">
      {loading ? (
        <p className="muted" role="status">
          Loading your questions
        </p>
      ) : turns.length === 0 ? (
        <EmptyState title="Nothing asked yet">
          <p>Ask a question above, or open Explain on a decision, an approval or a finding.</p>
        </EmptyState>
      ) : (
        <ul className="turn-list">
          {turns.map((turn) => (
            <li key={turn.turn_id}>
              <Link to="/ask/$turnId" params={{ turnId: turn.turn_id }}>
                {turnTitle(turn)}
              </Link>
              <span className="turn-list-meta">
                <Badge tone={tone(turn.state)}>{WORDS[turn.state] ?? turn.state}</Badge>
                <span className="mono">{when(turn.created_at)}</span>
              </span>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

const WORDS: Record<string, string> = {
  RUNNING: "Working",
  COMPLETED: "Answered",
  FAILED: "Stopped",
};
