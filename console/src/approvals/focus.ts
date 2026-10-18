// SPDX-License-Identifier: AGPL-3.0-only
// Where the focus lands when a row opens its detail: on the detail's title, so the next Tab
// reaches the comment and the two buttons, rather than on the page heading as a navigation
// between pages would put it (#333).

let pending = false;

export function focusDetailNext(): void {
  pending = true;
}

/** Whether the detail should take the focus now; asking consumes the request. */
export function takeDetailFocus(): boolean {
  const take = pending;
  pending = false;
  return take;
}
