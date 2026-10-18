// SPDX-License-Identifier: AGPL-3.0-only
import { toast } from "../../lib/toast";
import { Button } from "../ui/Button";

/** A command or a configuration to copy: shown as text, with a button that copies it exactly. */
export function Snippet({ label, value }: { label: string; value: string }) {
  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      toast(`${label} copied.`);
    } catch {
      toast("Copying failed; select the text and copy it yourself.");
    }
  }
  return (
    <>
      <pre aria-label={label} tabIndex={0}>
        <code>{value}</code>
      </pre>
      <Button
        size="small"
        onClick={() => {
          void copy();
        }}
      >
        Copy {label.toLowerCase()}
      </Button>
    </>
  );
}
