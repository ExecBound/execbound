# SPDX-License-Identifier: AGPL-3.0-only
"""Short-lived navigation back to a console page; never authentication or review authority.

The hint is one signed cookie naming where a person was when their session ended, or which page
a link opened while they were signed out, so that signing in returns them there. What it may
name is a closed grammar, `canonical`: core's own console route shapes with lowercase-UUID
parameters, and on five pages a few query keys whose values are UUIDs or closed enumerations.
Every page a hint returns to re-authorises its reads; the hint itself grants nothing (#678).
"""

import functools
import hashlib
import hmac
import re
from collections.abc import Callable
from typing import TYPE_CHECKING
from urllib.parse import parse_qsl, urlencode
from uuid import UUID

from fastapi import HTTPException, Request
from starlette.responses import Response

from execbound.plugins import LoadedPlugins
from execbound.surfaces.sections import SECTIONS

if TYPE_CHECKING:
    from execbound.runtime import Runtime
    from execbound.surfaces.human import HumanConfig

TTL = 300
_ID = r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}"
_UUID = re.compile(_ID)
_DOMAIN = b"execbound.login-return.v1:"
# What a target may be before it is parsed, and what the canonical form may be after.
TARGET_MAX = 512
CANONICAL_MAX = 256
_FIELDS_MAX = 16
# Encoded separators, a fragment, a backslash, whitespace and control characters: none can be
# part of a console address this grammar admits, so any of them refuses the whole target.
_REFUSED = re.compile(r"[\\#\s\x00-\x1f\x7f]|%(?:2f|5c)", re.IGNORECASE)

# Home's ranges: `console/src/lib/words.ts`'s `RANGES`.
HOME_RANGES = ("24h", "7d", "30d")
# The Approvals page's views: `console/src/approvals/search.ts`'s `APPROVALS_VIEWS`. The page
# shows `others` only to an administrator and coerces it to Pending for anyone else.
APPROVAL_VIEWS = ("pending", "decided", "lapsed", "others")
# Monitoring's views: `console/src/components/monitor/search.ts`'s `VIEWS`, which `views.ts`
# re-exports. Not `console.MONITOR_VIEWS`, the legacy `/monitor/{view}` redirects' list, whose
# members differ.
MONITOR_SEARCH_VIEWS = ("connections", "inventory", "agents", "activity", "findings", "alerts")
# Monitoring's finding states and its one `focus` value: the same file's `STATES` and the
# literal `parseMonitorSearch` admits.
FINDING_STATES = ("open", "acknowledged", "all")
MONITOR_FOCUS = ("quiet",)
# Getting started's steps: `console/src/components/welcome/steps.ts`'s `STEPS`.
WELCOME_STEPS = ("example", "connect", "verify", "controls")


def _one_of(values: tuple[str, ...]) -> Callable[[str], bool]:
    return lambda value: value in values


def _identifier(value: str) -> bool:
    return _UUID.fullmatch(value) is not None


def _activity_state(value: str) -> bool:
    from execbound.surfaces.human import ACTIVITY_STATES

    return value in ACTIVITY_STATES


def _since(value: str) -> bool:
    from execbound.surfaces.console_api.executions import SINCE

    return value in SINCE


def _action(value: str) -> bool:
    from execbound.operations import PRODUCTION_ACTIONS

    return value in PRODUCTION_ACTIONS.names


def _outcome(value: str) -> bool:
    from execbound.surfaces.outcomes import OUTCOMES

    return value in OUTCOMES


# The query keys a returned page keeps, by page, each with the check its value must pass; every
# other key is dropped. No admitted key may cause a change when the page loads: each one only
# selects what the page shows (a view, a filter, a record to open, a step to show), and the page
# acts only on a click. A key is added here only after its page has been checked to act on a
# click alone, and the reviewer of that change confirms it. Activity's `cursor` and `from`,
# Monitoring's `story`, `setup` and `connect` are never kept: a cursor and an instant page into
# a result that has moved by the time the person is back, a story id admits `:`, and the last
# two open a dialog or report a one-time result. No page keeps free text.
_QUERY: dict[str, dict[str, Callable[[str], bool]]] = {
    "/": {"open": _identifier, "range": _one_of(HOME_RANGES)},
    "/activity": {
        "open": _identifier,
        "agent": _identifier,
        "target": _identifier,
        "state": _activity_state,
        "since": _since,
        "action": _action,
        "outcome": _outcome,
    },
    "/approvals": {"view": _one_of(APPROVAL_VIEWS)},
    "/monitor": {
        "view": _one_of(MONITOR_SEARCH_VIEWS),
        "state": _one_of(FINDING_STATES),
        "open": _identifier,
        "focus": _one_of(MONITOR_FOCUS),
    },
    "/welcome": {"step": _one_of(WELCOME_STEPS)},
}


@functools.cache
def _shapes(scoped: bool) -> re.Pattern[str]:
    """Core's console routes as one expression, each parameter a lowercase UUID and each
    approval page with its classic form. A plugin's own console pages are not among them: core
    does not know their parameters or what their queries mean."""
    # `console` imports this module, so its routes are read here, once per answer.
    from execbound.surfaces.console import CONSOLE_ROUTES, SCOPED_APPROVAL_ROUTE

    routes = CONSOLE_ROUTES + ((SCOPED_APPROVAL_ROUTE,) if scoped else ())
    parts = []
    for route in routes:
        pattern = "".join(
            _ID if piece.startswith("{") else re.escape(piece)
            for piece in re.split(r"(\{[^}]+\})", route)
        )
        if route.endswith("/approvals/{approval_id}"):
            pattern += "(?:/classic)?"
        parts.append(pattern)
    return re.compile("(?:" + "|".join(parts) + ")")


def canonical(target: object, plugins: LoadedPlugins) -> str | None:
    """The one form of a console address a hint may carry, or `None` where it may carry none.

    A core console page, then only the query keys its page keeps, with values that pass their
    checks, in sorted order. A duplicated key or a query that does not parse refuses the target;
    any other key or value is dropped.
    """
    if type(target) is not str or len(target) > TARGET_MAX:
        return None
    if not target.startswith("/") or target.startswith("//") or _REFUSED.search(target):
        return None
    path, _, query = target.partition("?")
    if not _shapes(plugins.approval_links is not None).fullmatch(path):
        return None
    try:
        pairs = parse_qsl(query, keep_blank_values=True, max_num_fields=_FIELDS_MAX)
    except ValueError:
        return None
    keys = [key for key, _ in pairs]
    if len(keys) != len(set(keys)):
        return None
    allowed = _QUERY.get(path, {})
    kept = sorted((key, value) for key, value in pairs if key in allowed and allowed[key](value))
    result = path + ("?" + urlencode(kept) if kept else "")
    # The cookie's value is split on `:`. No shape holds one and `urlencode` escapes one in a
    # value, so the second condition never refuses anything; it is the format's guard.
    if len(result) > CANONICAL_MAX or ":" in result:
        return None
    return result


def login_location(target: str, plugins: LoadedPlugins) -> str:
    """Sign-in, carrying `target` as the hint when it is a console page other than Home's bare
    address, which is where a sign-in with no hint lands anyway."""
    returned = canonical(target, plugins)
    if returned is None or returned == "/":
        return "/login"
    return "/login?" + urlencode({"review": returned})


def remember(
    request: Request, response: Response, config: "HumanConfig", runtime: "Runtime"
) -> Response:
    """Keep `?review=` as the hint, or ignore one the grammar cannot use.

    An unusable hint (a stale tab, a route this server does not have, a hand-typed address)
    still reaches sign-in; it also deletes any hint the browser already holds, so an earlier one
    cannot carry the person anywhere but the landing page after a garbled link.
    """
    target = request.query_params.get("review")
    if target is None:
        return response
    returned = canonical(target, runtime.plugins)
    if returned is None:
        response.delete_cookie(
            config.cookie("review_return"),
            path="/",
            secure=config.secure,
            httponly=True,
            samesite="lax",
        )
        return response
    return _write(response, config, runtime, returned)


def remember_path(
    response: Response, config: "HumanConfig", runtime: "Runtime", path: str
) -> Response:
    """Retain a navigation hint through MFA; it never grants membership or review authority."""
    returned = canonical(path, runtime.plugins)
    if returned is None:
        raise HTTPException(400, "Invalid request")
    return _write(response, config, runtime, returned)


def remember_section(
    response: Response, config: "HumanConfig", runtime: "Runtime", section: str
) -> Response:
    """Retain the console section a workspace switch lands on, through the second factor.

    Only the switch route calls this, behind its CSRF check, and it writes nothing but a
    section root: each is a core console page with no parameter, so its canonical form is
    itself and `destination` reads it back as it reads any other hint.
    """
    if section not in SECTIONS:
        raise HTTPException(400, "Invalid request")
    returned = canonical(section, runtime.plugins)
    if returned is None:
        raise HTTPException(400, "Invalid request")
    return _write(response, config, runtime, returned)


def _write(response: Response, config: "HumanConfig", runtime: "Runtime", path: str) -> Response:
    expires = int(runtime.clock.now().timestamp()) + TTL
    keys = config.keys
    value = f"{keys.active_key_id}:{expires}:{path}"
    signature = hmac.new(keys.keys[keys.active_key_id], _DOMAIN + value.encode(), hashlib.sha256)
    response.set_cookie(
        config.cookie("review_return"),
        value + ":" + signature.hexdigest(),
        max_age=TTL,
        secure=config.secure,
        httponly=True,
        samesite="lax",
        path="/",
    )
    return response


_SCOPED = re.compile(rf"/workspaces/({_ID})/approvals/")


def hinted_workspace(request: Request, config: "HumanConfig", runtime: "Runtime") -> UUID | None:
    """The workspace a signed hint's workspace-scoped approval address names, or `None`.

    It reads the same signed, short-lived, single cookie `destination` reads, and nothing else.
    A sign-in passes it as a preference among the account's own usable memberships, so it can
    only choose which of them the sign-in opens, never add one (#678).
    """
    found = _SCOPED.match(destination(request, config, runtime, ""))
    return UUID(found.group(1)) if found else None


def destination(request: Request, config: "HumanConfig", runtime: "Runtime", fallback: str) -> str:
    # Lax lets an OAuth callback read this navigation hint. The actual session stays Strict.
    # Check duplicate cookies as well as the MAC, the deadline and that the value is its own
    # canonical form.
    name = config.cookie("review_return")
    if (
        sum(
            part.strip().startswith(name + "=")
            for part in request.headers.get("cookie", "").split(";")
        )
        != 1
    ):
        return fallback
    value = request.cookies.get(name, "")
    if len(value) > 400:
        return fallback
    try:
        key_id, expiry, path, signature = value.split(":")
        key = config.keys.keys[key_id]
        remaining = int(expiry) - int(runtime.clock.now().timestamp())
    except (ValueError, KeyError):
        return fallback
    if not 0 < remaining <= TTL or canonical(path, runtime.plugins) != path:
        return fallback
    expected = hmac.new(key, _DOMAIN + value.rsplit(":", 1)[0].encode(), hashlib.sha256).hexdigest()
    return path if hmac.compare_digest(signature.encode(), expected.encode()) else fallback
