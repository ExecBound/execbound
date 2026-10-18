// SPDX-License-Identifier: AGPL-3.0-only
// Toasts after a change (#333), announced in a polite live region. A store rather
// than a library: the ones on the registry inject a <style> element the policy refuses.

import { useSyncExternalStore } from "react";

export interface Toast {
  id: number;
  text: string;
}

const DURATION_MS = 6000;
let toasts: Toast[] = [];
let next = 1;
const listeners = new Set<() => void>();

function emit(): void {
  for (const listener of listeners) listener();
}

export function toast(text: string, duration = DURATION_MS): number {
  const id = next++;
  toasts = [...toasts, { id, text }];
  emit();
  if (duration > 0) {
    setTimeout(() => {
      dismiss(id);
    }, duration);
  }
  return id;
}

export function dismiss(id: number): void {
  if (!toasts.some((item) => item.id === id)) return;
  toasts = toasts.filter((item) => item.id !== id);
  emit();
}

export function clearToasts(): void {
  toasts = [];
  emit();
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

export function useToasts(): Toast[] {
  return useSyncExternalStore(
    subscribe,
    () => toasts,
    () => toasts,
  );
}
