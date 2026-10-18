// SPDX-License-Identifier: AGPL-3.0-only
import { useState } from "react";

import { Button } from "../ui/Button";
import { Field, Problem } from "./forms";

/**
 * One quiet field under the heading of an agent or a person with no label (#678): a name makes
 * them recognisable in approvals and Activity, where they otherwise read "Agent 3" or "User 3".
 * It submits through the same change the Identity card makes, so the server's screen, the
 * step-up a person's label needs and the refusal copy are the ones already there. Nothing is
 * optimistic: the prompt goes when the page reads a label the server saved.
 */
export function NamePrompt({
  noun,
  onSave,
  pending,
  error,
}: {
  noun: "Agent" | "User";
  onSave: (label: string) => void;
  pending: boolean;
  error: unknown;
}) {
  const [label, setLabel] = useState("");
  const agent = noun === "Agent";
  return (
    <form
      className="form-row name-prompt"
      aria-label={agent ? "Name this agent" : "Name this person"}
      onSubmit={(event) => {
        event.preventDefault();
        onSave(label.trim());
      }}
    >
      <p className="muted">
        {agent
          ? "Name this agent so teammates recognise it in approvals and Activity."
          : "Name this person so teammates recognise them in approvals and Activity."}
      </p>
      <Field label={agent ? "Agent name" : "Name"}>
        <input
          value={label}
          maxLength={80}
          required
          autoComplete="off"
          onChange={(event) => {
            setLabel(event.target.value);
          }}
        />
      </Field>
      <Button type="submit" disabled={pending}>
        Save name
      </Button>
      <Problem error={error} />
    </form>
  );
}
