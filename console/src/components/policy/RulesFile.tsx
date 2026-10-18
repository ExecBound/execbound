// SPDX-License-Identifier: AGPL-3.0-only
// Rules files (#678): a policy's rules downloaded as the file `ruleset-compile` reads,
// and a draft started from one. Neither carries this workspace's record identifiers, and the
// file a person picks is held in this component's state only until its request settles.
import { useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { useState } from "react";

import { createPolicyBundleMutation } from "../../api/@tanstack/react-query.gen";
import { readPolicyRulesFile } from "../../api/sdk.gen";
import type { RulesFileSummary } from "../../api/types.gen";
import { useServerMutation } from "../../lib/mutation";
import { toast } from "../../lib/toast";
import { explain, refusalOf } from "../directory/errors";
import { Field, Problem } from "../directory/forms";
import { Button } from "../ui/Button";
import "./policy.css";

/** At most this many bytes, as the server's `MAX_RULESET_FILE_BYTES`. */
export const RULES_FILE_BYTES = 512 * 1024;

/** What a downloaded file leaves out, before the person clicks. */
export function rulesFileNote(summary: RulesFileSummary): string {
  const left: string[] = [];
  const count = summary.omitted_budgets.length;
  if (count > 0) {
    left.push(
      `${String(count)} budget${count === 1 ? "" : "s"} counted for a named group, account or Space (${summary.omitted_budgets.join(", ")})`,
    );
  }
  if (summary.omitted_context) left.push("this policy's context settings");
  const kept = "Rule notes and condition values are included as written.";
  if (left.length === 0) return kept;
  return `The file leaves out ${left.join(" and ")}, because those name this workspace's own records. ${kept}`;
}

/**
 * Download rules: the file is built here from the server's answer, as text, and handed to the
 * browser as a download. Nothing is cached and nothing reaches an HTML sink.
 */
export function DownloadRules({
  bundleId,
  summary,
  origin,
}: {
  bundleId: string;
  summary: RulesFileSummary | undefined;
  origin: "rules" | "recognized-seed" | "cedar" | undefined;
}) {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);
  if (summary?.available !== true) {
    return (
      <p className="muted">
        {origin === "recognized-seed"
          ? "Create an editable draft first to download its rules."
          : "Written in Cedar, so it cannot be downloaded as rules. Copy its complete configuration under Advanced instead."}
      </p>
    );
  }
  const save = async () => {
    setPending(true);
    setError(null);
    try {
      const { data } = await readPolicyRulesFile({ path: { bundle_id: bundleId }, throwOnError: true });
      const blob = new Blob([`${JSON.stringify(data.ruleset, null, 2)}\n`], { type: "application/json" });
      const address = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = address;
      anchor.download = data.filename;
      anchor.rel = "noopener";
      anchor.click();
      setTimeout(() => {
        URL.revokeObjectURL(address);
      }, 0);
    } catch (refused) {
      setError(refused);
    } finally {
      setPending(false);
    }
  };
  return (
    <div className="policy-rules-file">
      <Button
        disabled={pending}
        onClick={() => {
          void save();
        }}
      >
        Download rules
      </Button>
      <p className="muted">{rulesFileNote(summary)}</p>
      <Problem error={error} />
    </div>
  );
}

interface Named {
  action?: unknown;
}

/** The action at a refusal's location, read from the person's own file. */
function actionAt(text: string, location: string): { action: string; place: string } | null {
  const match = /^ruleset\.(rules|budgets)\.(\d+)\.(action|actions\.(\d+))$/.exec(location);
  if (match === null) return null;
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return null;
  }
  if (typeof value !== "object" || value === null) return null;
  const list: unknown = (value as Record<string, unknown>)[match[1] ?? ""];
  if (!Array.isArray(list)) return null;
  const index = Number(match[2]);
  const item: unknown = list[index];
  if (typeof item !== "object" || item === null) return null;
  let action: unknown = (item as Named).action;
  if (match[4] !== undefined) {
    const actions: unknown = (item as Record<string, unknown>).actions;
    action = Array.isArray(actions) ? actions[Number(match[4])] : undefined;
  }
  if (typeof action !== "string") return null;
  const place = match[1] === "rules" ? `rule ${String(index + 1)}` : `budget ${String(index + 1)}`;
  return { action, place };
}

/** One sentence for a refused rules file, worded from the file itself where the refusal
 *  names an action, else the shared refusal copy. */
export function rulesFileRefusal(error: unknown, text: string): string {
  const refusal = refusalOf(error);
  const named = refusal.fields
    .map((field) => actionAt(text, field))
    .filter((item): item is { action: string; place: string } => item !== null);
  if (named.length > 0) {
    const list = named.map((item) => `${item.action} (${item.place})`).join(", ");
    if (refusal.code === "INVALID_BODY") {
      return `This Space has no action mapping for ${list}. Remove those rules or ask your operator to add the mapping.`;
    }
    if (refusal.code === "SIGNAL_MAPPING_ONLY") {
      return `${list} is served in this Space only by a signal mapping, which a rules file cannot carry. Paste the complete bundle under Advanced instead, or ask your operator.`;
    }
    if (refusal.code === "MAPPINGS_CONFLICT") {
      return `Two mappings serve ${list} and cannot share one policy. Ask your operator to choose one with ruleset-compile --ref, then paste the bundle it prints.`;
    }
  }
  return explain(error);
}

/** Start from a rules file: a draft here, over this Space's own action mappings. */
export function RulesFileDraft() {
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  // The chosen file's text, held only until its request settles and never stored.
  const [text, setText] = useState<string | null>(null);
  const [tooLarge, setTooLarge] = useState(false);
  // A refusal is worded from the file that was sent, once, when it is refused.
  const [refusal, setRefusal] = useState<string | null>(null);
  const create = useServerMutation({
    ...createPolicyBundleMutation(),
    onSuccess: (made) => {
      toast("Draft created from the rules file. Validate it, then preview what it would change.");
      void queryClient.invalidateQueries({ queryKey: [{ _id: "listPolicy" }] });
      void navigate({ to: "/policy/$bundleId", params: { bundleId: made.bundle_id } });
    },
    onError: (error, variables) => {
      setRefusal(rulesFileRefusal(error, variables.body.ruleset ?? ""));
    },
    onSettled: () => {
      setText(null);
    },
  });
  return (
    <section>
      <h3>Start from a rules file</h3>
      <p>
        A rules file downloaded from another workspace, or written for ruleset-compile. It becomes
        a draft here, over this Space&rsquo;s own action mappings, and still has to be validated,
        previewed and activated.
      </p>
      <Field label="Rules file (JSON, at most 512 KB)">
        <input
          type="file"
          accept=".json,application/json"
          onChange={(event) => {
            const file = event.target.files?.[0];
            setTooLarge(false);
            setRefusal(null);
            setText(null);
            if (file === undefined) return;
            // Bytes, as the server counts them, and before anything is read.
            if (file.size > RULES_FILE_BYTES) {
              setTooLarge(true);
              return;
            }
            void file.text().then(setText);
          }}
        />
      </Field>
      {tooLarge ? <p className="problem" role="alert">The file is larger than 512 KB.</p> : null}
      <div className="policy-actions">
        <Button
          variant="primary"
          disabled={create.isPending || text === null}
          onClick={() => {
            if (text === null) return;
            setRefusal(null);
            create.mutate({ body: { source: "ruleset", ruleset: text } });
          }}
        >
          Create draft from file
        </Button>
      </div>
      {refusal === null ? null : <p className="problem" role="alert">{refusal}</p>}
    </section>
  );
}
