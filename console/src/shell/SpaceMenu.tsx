// SPDX-License-Identifier: AGPL-3.0-only
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { useEffect, useRef, useState } from "react";

import type { SpaceRow } from "../api/types.gen";
import { useSession } from "../lib/session";
import { listSpacesOptions } from "../lib/shell-api";
import { useSpaceSwitch } from "../lib/spaces";
import { Icon } from "./icons";
import { moveOption, trapPopoverKeys, useOutsidePress } from "./listbox";
import { ALL } from "./SpaceSwitcher";

const SETTLE_MS = 150;
const FILTER_MAX = 80;

/**
 * The listbox. Focus is trapped inside it, Escape closes it and gives the trigger its focus
 * back, and a press anywhere else closes it. The filter is the server's: it asks
 * `GET /spaces?q=` once the typing settles, so the list is the person's visible set and never
 * a client-side narrowing of a page of it.
 */
export default function SpaceMenu({ onClose, onCreate }: { onClose: () => void; onCreate: () => void }) {
  const session = useSession();
  const navigate = useNavigate();
  const panel = useRef<HTMLDivElement | null>(null);
  const filter = useRef<HTMLInputElement | null>(null);
  const [query, setQuery] = useState("");
  const [settled, setSettled] = useState("");
  const [archived, setArchived] = useState(false);
  const switcher = useSpaceSwitch(onClose);

  useEffect(() => {
    const timer = setTimeout(() => {
      setSettled(query.trim().slice(0, FILTER_MAX));
    }, SETTLE_MS);
    return () => {
      clearTimeout(timer);
    };
  }, [query]);

  useEffect(() => {
    filter.current?.focus();
  }, []);

  useOutsidePress(panel, onClose);

  const spaces = useQuery({
    ...listSpacesOptions({
      query: {
        state: archived ? "all" : "active",
        ...(settled === "" ? {} : { q: settled }),
      },
    }),
    staleTime: 10_000,
  });
  const rows: SpaceRow[] = spaces.data?.items ?? [];
  const administrator = spaces.data?.administrator ?? false;
  const current = session.space?.id ?? ALL;
  const options: { id: string; name: string; note: string }[] = [
    ...(session.allSpaces ? [{ id: ALL, name: "All spaces", note: "Everything you can see" }] : []),
    ...rows.map((row) => ({
      id: row.space_id,
      name: row.name,
      note: row.archived_at === null ? (row.detail ?? "") : "Archived",
    })),
  ];

  return (
    <div
      ref={panel}
      className="switcher-pop"
      onKeyDown={(event) => {
        trapPopoverKeys(event, panel, onClose);
      }}
    >
      {/* The tenant, named where the space is chosen. On a phone the top bar has no room
          for a detail line under the name, so this is where the boundary is read. */}
      <p className="switcher-tenant">
        <span>Tenant</span>
        <strong>{session.tenant.name}</strong>
      </p>
      <div className="switcher-filter">
        <Icon name="search" size={16} />
        <input
          ref={filter}
          type="text"
          value={query}
          maxLength={FILTER_MAX}
          aria-label="Filter spaces"
          placeholder="Filter spaces"
          onChange={(event) => {
            setQuery(event.target.value);
          }}
          onKeyDown={(event) => {
            if (event.key !== "ArrowDown") return;
            event.preventDefault();
            panel.current?.querySelector<HTMLElement>('[role="option"]')?.focus();
          }}
        />
      </div>
      <ul className="switcher-list" role="listbox" aria-label="Spaces">
        {options.map((option, index) => (
          <li
            key={option.id}
            role="option"
            aria-selected={option.id === current}
            tabIndex={index === 0 ? 0 : -1}
            className="switcher-option"
            onClick={() => {
              if (option.id === current) {
                onClose();
                return;
              }
              switcher.mutate({
                space: option.id === ALL ? null : option.id,
                name: option.id === ALL ? null : option.name,
              });
            }}
            onKeyDown={(event) => {
              if (event.key === "ArrowDown" || event.key === "ArrowUp") {
                event.preventDefault();
                moveOption(event.currentTarget, event.key === "ArrowDown" ? 1 : -1);
                return;
              }
              if (event.key !== "Enter" && event.key !== " ") return;
              event.preventDefault();
              event.currentTarget.click();
            }}
          >
            <span className="switcher-name">
              <strong>{option.name}</strong>
              {option.note !== "" ? <small>{option.note}</small> : null}
            </span>
            {option.id === current ? <Icon name="check" size={16} /> : null}
          </li>
        ))}
      </ul>
      {spaces.isPending ? <p className="switcher-note">Loading the spaces.</p> : null}
      {!spaces.isPending && options.length === 0 ? (
        <p className="switcher-note">No space matches.</p>
      ) : null}
      {spaces.isError ? (
        <p className="switcher-note" role="alert">
          The spaces could not be read.
        </p>
      ) : null}
      <div className="switcher-foot">
        <label className="switcher-archived">
          <input
            type="checkbox"
            checked={archived}
            onChange={(event) => {
              setArchived(event.target.checked);
            }}
          />
          Show archived
        </label>
        {administrator ? (
          <>
            <button type="button" className="switcher-action" onClick={onCreate}>
              <Icon name="tenant" size={16} />
              New space
            </button>
            <button
              type="button"
              className="switcher-action"
              onClick={() => {
                onClose();
                void navigate({ to: "/spaces" });
              }}
            >
              <Icon name="arrow" size={16} />
              Manage spaces
            </button>
          </>
        ) : null}
      </div>
    </div>
  );
}
