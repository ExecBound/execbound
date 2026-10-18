// SPDX-License-Identifier: AGPL-3.0-only
import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { connectTinesMutation, readMonitorQueryKey } from "../../api/@tanstack/react-query.gen";
import { useServerMutation } from "../../lib/mutation";
import { Button } from "../ui/Button";
import { DialogClose, DialogSurface, DialogTitle } from "../ui/dialog";
import { Field } from "../ui/Field";
import { archivedWords, connectCopy, placementWords, reviewedWords, tinesFaults, type TinesForm, usePlacement } from "./connect";

/** The hint and the fault a control is described by, where its field shows them. */
function described(id: string, hint: boolean, fault: boolean): string | undefined {
  const ids = [hint ? `${id}-hint` : "", fault ? `${id}-fault` : ""].filter((value) => value !== "");
  return ids.length === 0 ? undefined : ids.join(" ");
}

const EMPTY: TinesForm = { label: "Tines", url: "", team: "", key: "" };
// What a refused field is called on this form, for the refusal line.
const FIELDS: Record<string, string> = {
  label: "Name the connection in 1 to 96 characters, without anything that reads as a secret.",
  base_url: "Use your Tines tenant's address, such as https://your-tenant.tines.com.",
  team_id: "A team ID is letters, digits, dots, colons, underscores or hyphens.",
  api_key: "Paste the API key without spaces.",
};

/**
 * Connect Tines (#228, #678): what ExecBound reads, then a read-only API key pasted once. The
 * server seals the key for ExecBound's collector before it is stored, so this web service cannot
 * read it back. Where the connection would land takes none (no Space chosen, an archived one, or
 * one this administrator only reviews), the first step says so and goes no further, so no key is
 * asked for. The key lives in this component's state alone: the change is sent with a mutation
 * kept for no time at all, and the key is cleared when it succeeds, fails or the dialog closes.
 * A refusal for a stale factor opens the step-up through the shared mutation path, which sends
 * the change again once. Success opens verification for the new connection.
 */
export function ConnectTines({ onClose, onConnected }: { onClose: () => void; onConnected: (connectionId: string) => void }) {
  const queryClient = useQueryClient();
  const [step, setStep] = useState(1);
  const [form, setForm] = useState<TinesForm>(EMPTY);
  const [touched, setTouched] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);
  const connecting = useServerMutation({
    ...connectTinesMutation(),
    gcTime: 0,
    onSuccess: (connection) => {
      setForm(EMPTY);
      connecting.reset();
      void queryClient.invalidateQueries({ queryKey: readMonitorQueryKey() });
      onConnected(connection.connection_id);
    },
    onError: (error) => {
      // The key goes with the attempt: a second try is pasted again.
      setForm((previous) => ({ ...previous, key: "" }));
      setProblem(connectCopy(error, FIELDS));
      connecting.reset();
    },
  });
  const faults = tinesFaults(form);
  const placement = usePlacement();
  const needsSpace = placement.choose;
  const archived = placement.archived;
  // A Space this administrator only reviews takes no connection from them: said before the step-up.
  const reviewed = placement.reviewed !== null;
  // Where it would land takes no connection: said on the first step, before the key is asked.
  const refused = needsSpace || archived || reviewed;
  const refusals = (
    <>
      {needsSpace ? <p role="alert">Close this and choose a Space before connecting.</p> : null}
      {archived ? <p role="alert">{archivedWords(placement, "connection")}</p> : null}
      {reviewed ? <p role="alert">{reviewedWords(placement, "connection")}</p> : null}
    </>
  );
  // Nothing is placed while where it lands is read again after the session moved.
  const ready = Object.keys(faults).length === 0 && !refused && !placement.checking;
  const shown = (field: keyof TinesForm) => (touched || form[field] !== EMPTY[field] ? faults[field] : undefined);
  const close = () => {
    setForm(EMPTY);
    onClose();
  };
  const submit = () => {
    setTouched(true);
    setProblem(null);
    if (!ready || connecting.isPending) return;
    const team = form.team.trim();
    connecting.mutate({
      body: { label: form.label.trim(), base_url: form.url.trim(), api_key: form.key, ...(team === "" ? {} : { team_id: team }) },
    });
  };
  return (
    <DialogSurface
      open
      onOpenChange={(open) => {
        if (!open && !connecting.isPending) close();
      }}
      className="dialog dialog-wide"
    >
      <header className="drawer-head">
        <DialogTitle className="drawer-title">Connect Tines</DialogTitle>
        <DialogClose className="btn btn-ghost" disabled={connecting.isPending}>
          Close
        </DialogClose>
      </header>
      <form
        noValidate
        autoComplete="off"
        onSubmit={(event) => {
          event.preventDefault();
          submit();
        }}
      >
        <div className="dialog-body">
          <p className="muted">Step {step} of 2 · {step === 1 ? "What ExecBound reads" : "Paste a read-only key"}</p>
          {step === 1 ? (
            <>
              <h3>What ExecBound reads</h3>
              <p>
                Use a service or team API key restricted to the teams being monitored, with read access to stories, actions
                and credential metadata. Audit and AI-audit access require the relevant Tines plan and permissions; the
                collector probes and reports what it can read.
              </p>
              <p>ExecBound reads metadata and audit records. It never runs, changes or deletes anything in Tines.</p>
              <p>Monitoring is visibility. It does not enforce action policy or prevent a Tines action from running.</p>
              {refusals}
            </>
          ) : (
            <>
              <Field id="tines-label" label="Connection name" error={shown("label")}>
                <input
                  id="tines-label"
                  value={form.label}
                  maxLength={96}
                  aria-invalid={shown("label") !== undefined}
                  aria-describedby={described("tines-label", false, shown("label") !== undefined)}
                  onChange={(event) => {
                    setForm({ ...form, label: event.target.value });
                  }}
                />
              </Field>
              <Field id="tines-url" label="Tines tenant URL" hint="https://your-tenant.tines.com" error={shown("url")}>
                <input
                  id="tines-url"
                  value={form.url}
                  inputMode="url"
                  spellCheck={false}
                  maxLength={260}
                  placeholder="https://your-tenant.tines.com"
                  aria-invalid={shown("url") !== undefined}
                  aria-describedby={described("tines-url", true, shown("url") !== undefined)}
                  onChange={(event) => {
                    setForm({ ...form, url: event.target.value });
                  }}
                />
              </Field>
              <Field id="tines-team" label="Team ID (optional)" hint="Leave blank to read every team the key can read." error={shown("team")}>
                <input
                  id="tines-team"
                  value={form.team}
                  spellCheck={false}
                  maxLength={64}
                  aria-invalid={shown("team") !== undefined}
                  aria-describedby={described("tines-team", true, shown("team") !== undefined)}
                  onChange={(event) => {
                    setForm({ ...form, team: event.target.value });
                  }}
                />
              </Field>
              <Field id="tines-key" label="API key" error={touched ? faults.key : undefined}>
                <input
                  id="tines-key"
                  type="password"
                  autoComplete="off"
                  spellCheck={false}
                  value={form.key}
                  maxLength={4096}
                  aria-invalid={touched && faults.key !== undefined}
                  aria-describedby={described("tines-key", false, touched && faults.key !== undefined)}
                  onChange={(event) => {
                    setForm({ ...form, key: event.target.value });
                  }}
                />
              </Field>
              <p>
                <strong>Placement:</strong> {placementWords(placement, "connection")}
              </p>
              {/* Said here too where it turns out only once the key is being asked, after the session moved. */}
              {refusals}
              <p>
                When you connect, the key is sealed for ExecBound&apos;s collector. This web service cannot read it back, and it is
                never shown again.
              </p>
              {problem !== null ? (
                <p role="alert" className="problem">
                  {problem}
                </p>
              ) : null}
            </>
          )}
        </div>
        <footer className="dialog-foot">
          {step === 2 ? (
            <Button
              disabled={connecting.isPending}
              onClick={() => {
                setStep(1);
              }}
            >
              Back
            </Button>
          ) : null}
          {step === 1 ? (
            <Button
              variant="primary"
              disabled={refused}
              onClick={() => {
                setStep(2);
              }}
            >
              Continue
            </Button>
          ) : (
            <Button type="submit" variant="primary" disabled={!ready || connecting.isPending} aria-busy={connecting.isPending}>
              {connecting.isPending ? "Connecting…" : "Connect"}
            </Button>
          )}
        </footer>
      </form>
    </DialogSurface>
  );
}
