// SPDX-License-Identifier: AGPL-3.0-only
import { dismiss, useToasts } from "../../lib/toast";
import { Icon } from "../../shell/icons";

/** Toasts land in a polite live region (#333); each can be dismissed. */
export function Toaster() {
  const toasts = useToasts();
  return (
    <div className="toasts" role="status" aria-live="polite">
      {toasts.map((item) => (
        <div key={item.id} className="toast">
          <span>{item.text}</span>
          <button
            type="button"
            className="btn btn-icon btn-ghost btn-small"
            aria-label="Dismiss"
            onClick={() => {
              dismiss(item.id);
            }}
          >
            <Icon name="close" size={16} />
          </button>
        </div>
      ))}
    </div>
  );
}
