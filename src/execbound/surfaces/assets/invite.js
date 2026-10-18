// SPDX-License-Identifier: AGPL-3.0-only
// Moves an invitation link's secret from the address bar into the form, and out of the
// address bar and this page's history entry, before anything else can read it. The secret
// never goes into storage, a query string or a request this script makes itself: the person
// presses Continue, and the form posts it. Without this script the page shows a paste box.
(function () {
  "use strict";
  var fragment = window.location.hash.slice(1);
  var field = document.getElementById("invite-token");
  var paste = document.getElementById("invite-paste");
  var go = document.getElementById("invite-continue");
  if (!field || !go) {
    return;
  }
  if (/^ebt1\.[0-9a-f-]{36}\.[0-9a-f-]{36}\.[A-Za-z0-9_-]{43}$/.test(fragment)) {
    field.value = fragment;
    window.history.replaceState(null, "", window.location.pathname);
    if (paste) {
      paste.hidden = true;
    }
    go.hidden = false;
    go.focus();
  } else if (window.location.hash) {
    window.history.replaceState(null, "", window.location.pathname);
  }
})();
