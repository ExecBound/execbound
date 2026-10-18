// SPDX-License-Identifier: AGPL-3.0-only
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState, useSyncExternalStore } from "react";

import { readSessionQueryKey, readSettingsOptions } from "../api/@tanstack/react-query.gen";
import { refusedChanges, subscribeRefused } from "../lib/step-up";
import { describe } from "../lib/step-up-purpose";
import { beginPasskey, verifyIdentity, verifyWithPasskey } from "../lib/verify-identity";
import {
  encodeAssertion,
  getAssertion,
  passkeysSupported,
  usableOptions,
  type PasskeyRequestOptions,
} from "../lib/webauthn";
import { Button } from "./ui/Button";
import { DialogClose, DialogSurface, DialogTitle } from "./ui/dialog";
import { Field } from "./ui/Field";

const WRONG =
  "That code could not be used. Enter a current authenticator code or an unused recovery code. After five failed attempts, wait 15 minutes.";
const EMPTY = "Enter a code from your authenticator app, or a recovery code.";
const UNAVAILABLE = "ExecBound could not check the code. Try again shortly.";
const CANCELLED = "The passkey prompt was cancelled or did not finish. Try again, or enter a code.";
const PASSKEY_REFUSED =
  "That passkey could not be used. Try it again, use another passkey saved to this account, or enter a code. After five failed attempts, wait 15 minutes.";
const AGAIN = "Choose Use a passkey again to continue.";
const GENERIC = "This change needs a recent second factor.";
/** Options are fetched fresh well inside the server's five minutes. */
const FRESH_MS = 4 * 60 * 1000;

interface Held {
  options: PasskeyRequestOptions;
  at: number;
}

function lowerFirst(text: string): string {
  return text.charAt(0).toLowerCase() + text.slice(1);
}

/** The question's first line: what was refused, in the purpose table's words and handles. */
function Purpose() {
  const queryClient = useQueryClient();
  const changes = useSyncExternalStore(subscribeRefused, refusedChanges);
  const phrases = [...new Set(changes.map((change) => describe(change, queryClient) ?? "Another protected change"))];
  const named = phrases.filter((phrase) => phrase !== "Another protected change");
  if (named.length === 0) return <p>{GENERIC}</p>;
  if (phrases.length === 1) return <p>To {lowerFirst(phrases[0] ?? "")}, confirm it is you.</p>;
  return (
    <>
      <p>To make these changes, confirm it is you:</p>
      <ul className="dialog-notes">
        {phrases.map((phrase) => (
          <li key={phrase}>{phrase}</li>
        ))}
      </ul>
    </>
  );
}

/**
 * The question itself (decided 28 September 2026), loaded by `StepUpHost` the first time a change
 * is refused MFA_REQUIRED: a dialog over whatever the page has open, which stays open and keeps
 * what was typed into it. Each question is a fresh instance, so it starts empty. A code accepted
 * here settles true and the fetch wrapper sends the change again; Cancel settles false and the
 * page says the change was not made. A wrong code says so here and can be tried again, within the
 * attempt limit the account security page already has.
 */
export function StepUpDialog({ open, onSettled }: { open: boolean; onSettled: (verified: boolean) => void }) {
  const [code, setCode] = useState("");
  const [problem, setProblem] = useState<string | undefined>(undefined);
  const [busy, setBusy] = useState(false);
  const field = useRef<HTMLInputElement | null>(null);
  const queryClient = useQueryClient();
  // A passkey: options are fetched as the dialog opens where the browser can ask, used once,
  // and fetched fresh after every finish attempt, since the server spends the challenge.
  const supported = passkeysSupported();
  // Whether the account has a passkey saved, from My account's own view; where that cannot be
  // read, the options request answers it (409 for none).
  const settings = useQuery({ ...readSettingsOptions(), enabled: open && supported, staleTime: 60_000 });
  const saved = settings.data?.security?.passkeys;
  const worth = saved === undefined ? settings.isError : saved > 0;
  const [offered, setOffered] = useState(false);
  const held = useRef<Held | null>(null);
  const loading = useRef(false);
  const [note, setNote] = useState("");
  const [passkeyProblem, setPasskeyProblem] = useState<string | undefined>(undefined);

  const refresh = () => {
    if (loading.current) return;
    loading.current = true;
    held.current = null;
    void beginPasskey().then((options) => {
      loading.current = false;
      if (usableOptions(options)) {
        held.current = { options, at: Date.now() };
        setOffered(true);
      } else {
        setOffered(false);
      }
    });
  };

  // Fetched as the question opens; each question is a fresh dialog.
  useEffect(() => {
    if (!open || !supported || !worth || loading.current) return;
    loading.current = true;
    void beginPasskey().then((options) => {
      loading.current = false;
      if (usableOptions(options)) {
        held.current = { options, at: Date.now() };
        setOffered(true);
      }
    });
  }, [open, supported, worth]);

  const usePasskey = () => {
    if (busy) return;
    setPasskeyProblem(undefined);
    const current = held.current;
    if (current === null || loading.current || Date.now() - current.at > FRESH_MS) {
      // Asking the browser after an await would leave the gesture: fetch, then ask for a
      // second click, which is a gesture of its own.
      setNote(AGAIN);
      refresh();
      return;
    }
    setNote("");
    // Called in the click itself, before anything is awaited.
    let asked: Promise<Credential | null>;
    try {
      asked = getAssertion(current.options);
    } catch {
      setPasskeyProblem(CANCELLED);
      refresh();
      return;
    }
    void (async () => {
      let credential: Credential | null;
      try {
        credential = await asked;
      } catch {
        // Cancelled or interrupted before reaching the server: the options are still unspent.
        setPasskeyProblem(CANCELLED);
        return;
      }
      if (credential === null) {
        setPasskeyProblem(CANCELLED);
        return;
      }
      setBusy(true);
      held.current = null;
      const outcome = await verifyWithPasskey(encodeAssertion(credential));
      setBusy(false);
      if (outcome === "verified") {
        void queryClient.invalidateQueries({ queryKey: readSessionQueryKey() });
        onSettled(true);
        return;
      }
      setPasskeyProblem(outcome === "refused" ? PASSKEY_REFUSED : UNAVAILABLE);
      // The attempt spent the challenge: the next click uses fresh options.
      refresh();
    })();
  };

  const submit = async () => {
    const value = code.replace(/\s+/g, "").toLowerCase();
    if (value === "") {
      setProblem(EMPTY);
      field.current?.focus();
      return;
    }
    setBusy(true);
    setProblem(undefined);
    const outcome = await verifyIdentity(value);
    setBusy(false);
    if (outcome === "verified") {
      // The session view carries the CSRF token too; read it again so every holder agrees.
      void queryClient.invalidateQueries({ queryKey: readSessionQueryKey() });
      onSettled(true);
      return;
    }
    setProblem(outcome === "refused" ? WRONG : UNAVAILABLE);
    setCode("");
    field.current?.focus();
  };

  return (
    <DialogSurface
      open={open}
      className="dialog dialog-over"
      backdropClassName="scrim scrim-over"
      initialFocus={field}
      onOpenChange={(next) => {
        if (!next && !busy) onSettled(false);
      }}
    >
      <form
        noValidate
        onSubmit={(event) => {
          event.preventDefault();
          if (!busy) void submit();
        }}
      >
        <header className="drawer-head">
          <DialogTitle className="drawer-title">Verify your identity</DialogTitle>
        </header>
        <div className="dialog-body">
          <Purpose />
          <p>
            {offered
              ? "Enter a code from your authenticator app or an unused recovery code, or use a passkey. Verification lasts thirty minutes and covers other protected changes."
              : "Enter a code from your authenticator app or an unused recovery code. Verification lasts thirty minutes and covers other protected changes."}
          </p>
          <Field id="step-up-code" label="Authentication code" error={problem}>
            <input
              id="step-up-code"
              ref={field}
              value={code}
              autoComplete="one-time-code"
              autoCapitalize="none"
              spellCheck={false}
              maxLength={64}
              disabled={busy}
              aria-invalid={problem !== undefined}
              aria-describedby={problem !== undefined ? "step-up-code-fault" : undefined}
              onChange={(event) => {
                setCode(event.target.value);
              }}
            />
          </Field>
          {offered ? (
            <div className="row">
              <Button type="button" disabled={busy} onClick={usePasskey}>
                Use a passkey
              </Button>
            </div>
          ) : null}
          {passkeyProblem !== undefined ? (
            <p className="problem" role="alert">
              {passkeyProblem}
            </p>
          ) : null}
          <p className="sr-only" role="status" aria-live="polite">
            {note}
          </p>
        </div>
        <footer className="dialog-foot">
          <DialogClose className="btn" disabled={busy}>
            Cancel
          </DialogClose>
          <Button type="submit" variant="primary" disabled={busy} aria-busy={busy}>
            Verify
          </Button>
        </footer>
      </form>
    </DialogSurface>
  );
}
