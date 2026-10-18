# SPDX-License-Identifier: AGPL-3.0-only
"""The signed sign-in hint names a console page from a closed grammar, and only that (#678).

`canonical` is the one check every reader and writer of the hint uses: core's own console route
shapes with lowercase-UUID parameters (the workspace-scoped approval shape only where a plugin's
approval links mount it), and on five pages the query keys their pages keep, whose values are
UUIDs or closed enumerations. The enumerations are the console's own, read from its source so the
two cannot drift. The cookie that carries a hint stays signed, five minutes long and single.
"""

import hashlib
import hmac
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
from starlette.requests import Request
from starlette.responses import Response

from execbound.plugins import NO_PLUGINS, ApprovalLinks, LoadedPlugins
from execbound.surfaces import login_return
from execbound.surfaces.console import CONSOLE_ROUTES, SCOPED_APPROVAL_ROUTE, core_console_routes
from execbound.surfaces.human import HumanConfig
from execbound.surfaces.login_return import canonical, destination, remember_path
from execbound.surfaces.tokens import TokenKeys

CONSOLE = Path(__file__).resolve().parents[1] / "console" / "src"
CONFIG = HumanConfig("http://127.0.0.1", TokenKeys("k1", {"k1": b"r" * 32}))


async def _review(request, runtime, config, session, csrf, tenant_id, approval_id, classic):
    return None


def _path(tenant_id, approval_id):
    return f"/workspaces/{tenant_id}/approvals/{approval_id}"


LINKED = LoadedPlugins(approval_links=ApprovalLinks(_path, _review))
PLUGIN_PAGE = LoadedPlugins(console_paths=("/invitations",))


class Clock:
    def __init__(self) -> None:
        self.value = datetime(2026, 10, 11, 12, tzinfo=UTC)

    def now(self) -> datetime:
        return self.value


def _runtime(plugins: LoadedPlugins = NO_PLUGINS):
    return SimpleNamespace(clock=Clock(), plugins=plugins)


def _filled(route: str) -> str:
    return re.sub(r"\{[^}]+\}", lambda _: str(uuid4()), route)


def _cookie(response: Response) -> str:
    values = [
        value.split(";", 1)[0].split("=", 1)[1]
        for value in response.headers.getlist("set-cookie")
        if value.startswith("eb_review_return=")
    ]
    assert len(values) == 1, values
    return values[0]


def _request(*cookies: str) -> Request:
    header = "; ".join(f"eb_review_return={value}" for value in cookies)
    return Request({"type": "http", "headers": [(b"cookie", header.encode())] if cookies else []})


def test_sn1_the_grammar_is_core_console_routes():
    for plugins in (NO_PLUGINS, LINKED):
        for route in core_console_routes(plugins):
            target = _filled(route)
            assert canonical(target, plugins) == target, target
            if route.endswith("/approvals/{approval_id}"):
                assert canonical(target + "/classic", plugins) == target + "/classic"
    assert canonical(_filled(SCOPED_APPROVAL_ROUTE), NO_PLUGINS) is None
    assert canonical(_filled(SCOPED_APPROVAL_ROUTE) + "/classic", NO_PLUGINS) is None
    # A plugin's own console page is not returnable: core does not know what it means.
    assert canonical("/invitations", PLUGIN_PAGE) is None
    record = str(uuid4())
    for refused in (
        "https://evil.example/",
        "//evil.example",
        "/approvals/../admin",
        "/%2Fevil",
        "/%2fevil",
        "/agents/%5C" + record,
        "/a\\b",
        "/activity#x",
        "/activity ?x",
        "/activity\t",
        "/activity\x00",
        "/agents/" + record.upper(),
        "/agents/not-a-uuid",
        "/agents/" + record + "/",
        "/" + "a" * 512,
        "/activity?open=" + "a" * 500,
        "/nowhere",
        "",
        "activity",
        None,
        b"/activity",
        ["/activity"],
    ):
        assert canonical(refused, LINKED) is None, refused


def test_sn2_only_known_keys_with_known_values_survive():
    record, other = str(uuid4()), str(uuid4())
    for target, kept in (
        (
            f"/activity?state=DENIED&open={record}&since=7d&agent={other}&target={record}"
            "&action=endpoint.isolate&outcome=approved&cursor=abc&q=free&from=2026-10-11T00:00:00Z",
            f"/activity?action=endpoint.isolate&agent={other}&open={record}&outcome=approved"
            f"&since=7d&state=DENIED&target={record}",
        ),
        ("/activity?state=NOPE&action=nope.nope&since=2y&outcome=nope", "/activity"),
        ("/activity?open=1", "/activity"),
        ("/activity?open=", "/activity"),
        ("/activity?", "/activity"),
        ("/activity?bare&&state=DENIED&", "/activity?state=DENIED"),
        ("/approvals?view=others", "/approvals?view=others"),
        ("/approvals?view=everything", "/approvals"),
        ("/approvals?view=pending+now", "/approvals"),
        (
            f"/monitor?view=findings&state=acknowledged&open={record}&focus=quiet&story=a:b",
            f"/monitor?focus=quiet&open={record}&state=acknowledged&view=findings",
        ),
        ("/monitor?view=nope&setup=tines&connect=done&focus=loud", "/monitor"),
        ("/welcome?step=connect", "/welcome?step=connect"),
        ("/welcome?step=<b>", "/welcome"),
        (f"/?range=7d&open={record}", f"/?open={record}&range=7d"),
        ("/?range=1y", "/"),
        (f"/agents/{record}?open={record}", f"/agents/{record}"),
        (f"/policy/{record}/rules?tab=raw", f"/policy/{record}/rules"),
    ):
        assert canonical(target, NO_PLUGINS) == kept, target
        # A canonical form is its own canonical form.
        assert canonical(kept, NO_PLUGINS) == kept
    # A key given twice refuses the whole target, as does a query past sixteen fields.
    assert canonical(f"/activity?open={record}&open={other}", NO_PLUGINS) is None
    assert canonical("/activity?state=DENIED&state=DENIED", NO_PLUGINS) is None
    assert canonical("/activity?" + "&".join(f"k{n}=v" for n in range(17)), NO_PLUGINS) is None
    assert canonical("/activity?" + "&".join(f"k{n}=v" for n in range(16)), NO_PLUGINS) == (
        "/activity"
    )
    # Every key a page keeps, each with the longest value it admits: still under 256, no `:`.
    longest = (
        f"/activity?open={record}&agent={record}&target={record}&state=FAILED_EFFECT_UNKNOWN"
        "&since=24h&outcome=would_refuse_by_limit&action=" + max(_actions(), key=len)
    )
    returned = canonical(longest, NO_PLUGINS)
    assert returned is not None and len(returned) <= 256 and ":" not in returned


def _actions() -> tuple[str, ...]:
    from execbound.operations import PRODUCTION_ACTIONS

    return tuple(PRODUCTION_ACTIONS.names)


def _console_list(file: str, name: str) -> tuple[str, ...]:
    """A `const NAME = [...] as const` array or a typed `NAME: readonly T[] = [...]` array from
    the console's source, as a tuple of its strings; a file or a name not found fails."""
    source = (CONSOLE / file).read_text(encoding="utf-8")
    found = re.search(
        rf"export const {name}(?::[^=]+)?\s*=\s*\[([^\]]*)\]", source, flags=re.DOTALL
    )
    assert found is not None, (file, name)
    return tuple(re.findall(r'"([^"]+)"', found.group(1)))


def test_sn2_the_enumerations_match_the_console():
    assert _console_list("lib/words.ts", "RANGES") == login_return.HOME_RANGES
    assert _console_list("approvals/search.ts", "APPROVALS_VIEWS") == login_return.APPROVAL_VIEWS
    union = re.search(
        r"export type ApprovalsView = ([^;]+);",
        (CONSOLE / "approvals/search.ts").read_text(encoding="utf-8"),
    )
    assert union is not None
    assert tuple(re.findall(r'"([^"]+)"', union.group(1))) == login_return.APPROVAL_VIEWS
    monitor = "components/monitor/search.ts"
    assert _console_list(monitor, "VIEWS") == login_return.MONITOR_SEARCH_VIEWS
    assert _console_list(monitor, "STATES") == login_return.FINDING_STATES
    focus = re.search(r'focus === "([a-z]+)"', (CONSOLE / monitor).read_text(encoding="utf-8"))
    assert focus is not None
    assert (focus.group(1),) == login_return.MONITOR_FOCUS
    assert _console_list("components/welcome/steps.ts", "STEPS") == login_return.WELCOME_STEPS
    # `views.ts` re-exports the views the grammar mirrors rather than holding a list of its own.
    assert 'export { VIEWS, type View } from "./search";' in (
        CONSOLE / "components/monitor/views.ts"
    ).read_text(encoding="utf-8")
    # Activity's states and windows are the server's own, which the console mirrors.
    from execbound.surfaces.console_api.executions import ACTIVITY_STATES, SINCE

    assert _console_list("lib/activity-search.ts", "ACTIVITY_STATES") == tuple(ACTIVITY_STATES)
    assert _console_list("lib/activity-search.ts", "SINCE") == tuple(SINCE)
    # The grammar's shapes are read from the route list, not a second copy of it.
    assert "/policy/{bundle_id}/rules" in CONSOLE_ROUTES


def test_sn3_a_hint_is_signed_short_lived_and_single():
    runtime = _runtime()
    record = str(uuid4())
    place = f"/activity?open={record}&state=DENIED"
    value = _cookie(remember_path(Response(), CONFIG, runtime, place))
    assert destination(_request(value), CONFIG, runtime, "/landing") == place
    # Written in any order and with keys the page does not keep, it is stored canonical.
    messy = f"/activity?state=DENIED&cursor=x&open={record}"
    assert _cookie(remember_path(Response(), CONFIG, runtime, messy)).split(":")[2] == place
    tampered = value[:-1] + ("0" if value[-1] != "0" else "1")
    assert destination(_request(tampered), CONFIG, runtime, "/landing") == "/landing"
    assert destination(_request(value, value), CONFIG, runtime, "/landing") == "/landing"
    unknown = "k2" + value[2:]
    assert destination(_request(unknown), CONFIG, runtime, "/landing") == "/landing"
    assert destination(_request("x" * 401), CONFIG, runtime, "/landing") == "/landing"
    later = _runtime()
    later.clock.value += timedelta(seconds=301)
    assert destination(_request(value), CONFIG, later, "/landing") == "/landing"
    # A value signed as this module signed one before the grammar widened still returns.
    approval = "/approvals/" + record
    expires = int(runtime.clock.now().timestamp()) + login_return.TTL
    signed = f"k1:{expires}:{approval}"
    mac = hmac.new(b"r" * 32, b"execbound.login-return.v1:" + signed.encode(), hashlib.sha256)
    assert destination(_request(signed + ":" + mac.hexdigest()), CONFIG, runtime, "/x") == approval
    # A correctly signed value that is not its own canonical form never returns.
    for raw in (f"/activity?cursor=x&open={record}", "//evil.example"):
        signed = f"k1:{expires}:{raw}"
        mac = hmac.new(b"r" * 32, b"execbound.login-return.v1:" + signed.encode(), hashlib.sha256)
        assert destination(_request(signed + ":" + mac.hexdigest()), CONFIG, runtime, "/x") == "/x"
    # The writer refuses what the grammar refuses.
    with pytest.raises(Exception, match="Invalid request"):
        remember_path(Response(), CONFIG, runtime, "/nowhere")


def test_sn3_sign_in_carries_a_page_but_never_home_bare():
    record = str(uuid4())
    assert login_return.login_location("/", NO_PLUGINS) == "/login"
    assert login_return.login_location("/nowhere", NO_PLUGINS) == "/login"
    assert login_return.login_location(f"/activity?open={record}", NO_PLUGINS) == (
        f"/login?review=%2Factivity%3Fopen%3D{record}"
    )
    assert login_return.login_location("/?range=7d", NO_PLUGINS) == "/login?review=%2F%3Frange%3D7d"


def test_sn1_the_character_checks_stand_without_the_shapes(monkeypatch):
    """The checks made before any shape is matched refuse on their own, so a route added to
    the tree with a looser shape still cannot carry a second origin or an encoded separator."""
    monkeypatch.setattr(login_return, "_shapes", lambda scoped: re.compile(r".*", re.DOTALL))
    for refused in ("//evil.example", "/a\\b", "/%2fevil", "/x%5Cy", "/x#y", "/x y", "/x\x7f"):
        assert canonical(refused, NO_PLUGINS) is None, refused
    assert canonical("/anything", NO_PLUGINS) == "/anything"
