// SPDX-License-Identifier: AGPL-3.0-only
import { useId, useState } from "react";

import { draftAssistantRuleMutation } from "../../api/@tanstack/react-query.gen";
import type { Proposed } from "../../api/types.gen";
import { useAssistant } from "../../lib/assistant";
import { useServerMutation } from "../../lib/mutation";
import { copyFor, refusal } from "../../lib/refusal";
import { Button } from "../ui/Button";
import { Card } from "../ui/Card";
import { describedBy, Field } from "../ui/Field";

const WORDS_LIMIT = 500;
const UNWRITABLE =
  "That could not be written as a rule. Say which action it is about, and which fact or " +
  "argument decides it.";

/**
 * The line a refusal reads as. `INVALID_PROPOSAL` is the server saying the model wrote a rule
 * the compiler will not take; it names the fields it failed at, which are for a reviewer
 * reading the network panel rather than for the person, who gets one sentence telling them
 * what to say instead.
 */
function refusalLine(error: unknown): string {
  return refusal(error).code === "INVALID_PROPOSAL" ? UNWRITABLE : copyFor(error);
}

/**
 * Describe a rule (#330, version 2).
 *
 * What comes back is a rule the compiler has already accepted, in the add-a-rule form's own
 * shape, with the sentence it reads as and its conditions in the words the editor parses. It
 * fills the form below beside the words that produced it. Nothing is added to the draft here: the
 * administrator reads the rule back as a sentence, edits it if they like, and presses Add the
 * rule, which is the same submission as any other. So the worst a bad description can do is
 * fill a form badly, and a description the compiler will not take is refused with the field
 * it failed at rather than half-applied.
 *
 * Absent where the operator configured no model, and not shown where the tenant's switch is
 * off, so a rules page that never had an assistant looks exactly as it did.
 */
export function DescribeRule({
  bundleId,
  editable,
  onProposed,
}: {
  bundleId: string;
  editable: boolean;
  onProposed: (proposal: Proposed) => void;
}) {
  const assistant = useAssistant();
  const id = useId();
  const [words, setWords] = useState("");
  const [proposed, setProposed] = useState<Proposed | undefined>(undefined);
  const draft = useServerMutation({
    ...draftAssistantRuleMutation(),
    onSuccess: (proposal: Proposed) => {
      setProposed(proposal);
      onProposed(proposal);
    },
  });
  if (!assistant.exists || !assistant.enabled || !editable) return null;
  return (
    <Card title="Describe a rule">
      <p className="muted">
        Say what the rule should do in your own words. What comes back is filled into the form
        below, where you read it back and decide; nothing is added to the draft until you press
        Add the rule.
      </p>
      <form
        onSubmit={(event) => {
          event.preventDefault();
          const said = words.trim();
          if (said === "") return;
          draft.mutate({ body: { bundle_id: bundleId, words: said } });
        }}
      >
        <Field
          id={`${id}-words`}
          label="What should the rule do?"
          hint="For example: never isolate a domain controller. Up to 500 characters."
          error={draft.isError ? refusalLine(draft.error) : undefined}
        >
          <textarea
            id={`${id}-words`}
            name="words"
            rows={2}
            maxLength={WORDS_LIMIT}
            required
            value={words}
            aria-describedby={describedBy(`${id}-words`)}
            onChange={(event) => {
              setWords(event.target.value);
            }}
          />
        </Field>
        <div className="policy-actions">
          <Button type="submit" disabled={draft.isPending || words.trim() === ""}>
            {draft.isPending ? "Drafting…" : "Describe a rule"}
          </Button>
        </div>
      </form>
      {proposed !== undefined ? (
        <div className="assistant-proposal" role="status">
          <p className="turn-label">
            Drafted from your words and filled into the form below. It becomes policy only when
            you add it.
          </p>
          <p>
            <strong>{proposed.sentence}</strong>
          </p>
          {proposed.lines.length > 0 ? (
            <ul className="plain">
              {proposed.lines.map((line) => (
                <li className="mono" key={line}>
                  {line}
                </li>
              ))}
            </ul>
          ) : null}
          <p className="muted">You wrote: {proposed.words}</p>
        </div>
      ) : null}
    </Card>
  );
}
