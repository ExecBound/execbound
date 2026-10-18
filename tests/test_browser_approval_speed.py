# SPDX-License-Identifier: AGPL-3.0-only
"""What an approval link costs on a mid-range phone (#333).

The person this page is built for is reading a notification on a phone, on mobile data, and
has not opened the console today: nothing is in the cache and their device is several times
slower than the machine this suite runs on. Within two and a half seconds of following the
link they must be able to read what is being asked and reach both decision buttons, and the
scripts and styles the route fetched to get there must stay inside the 160 KB the build
budgets for an approval link opened cold.

The throttle is Chrome's own "Fast 4G" preset, the figures DevTools sends over the protocol
(9 Mbit/s down and 1.5 Mbit/s up at nine tenths, 60 ms of round trip at two and three quarter
times), with `Emulation.setCPUThrottlingRate` at four. A deployment sits behind a proxy that
compresses and the application itself does not, so the fixture compresses as such a proxy
does: the bytes counted here are the bytes a browser receives from a deployed console.
Fonts and the API's own answers are outside the 160 KB, which is the route's code; both are
inside the two and a half seconds, which is what the person waits.

The figure runs a few kilobytes above the one `pnpm build` prints for the same route, and the
difference is real rather than a disagreement: the build reads Vite's manifest, which does not
list the document, the token stylesheet or the plain frame's, and a browser fetches all three.
What the two have in common is the unit, the compressed body of each file, which is why this
counts `encodedBodySize` and leaves one set of response headers per file out of the budget.

The machine that runs this suite may run others beside it, so the measurement is the
fastest of three cold loads. Contention on a shared machine is not what the budget is about,
and a regression in the application shows in every attempt rather than only the slowest.

The bytes are counted by a test of their own, outside the `timed` mark: what a load fetches
does not depend on how busy the machine is, so a run that deselects `timed` still checks the
budget.
"""

import contextlib
import functools
import time
from datetime import timedelta
from email.utils import format_datetime

import httpx
import pytest
from conftest import Machine
from playwright.sync_api import expect
from starlette.middleware.gzip import GZipMiddleware
from test_browser_console import console_app, sign_in_as
from test_browser_surfaces import chromium as chromium
from test_browser_surfaces import serve
from test_execution import registry as registry
from test_execution import request
from test_execution import world as world
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

from execbound.surfaces import console as console_module
from execbound.surfaces import sessions

# Chrome's "Fast 4G": 9 Mbit/s down and 1.5 Mbit/s up at nine tenths, 60 ms of round trip at
# two and three quarter times, in the bytes-per-second and milliseconds the protocol takes.
FAST_4G = {
    "offline": False,
    "downloadThroughput": int(9 * 1000 * 1000 / 8 * 0.9),
    "uploadThroughput": int(1.5 * 1000 * 1000 / 8 * 0.9),
    "latency": 60 * 2.75,
}
CPU_SLOWDOWN = 4
PHONE = {"width": 390, "height": 844}
TARGET_SECONDS = 2.5
BUDGET_BYTES = 160 * 1024
ATTEMPTS = 3
# The document, and every script and stylesheet the route asked for. `encodedBodySize` is the
# compressed body of each, which is what the budget is stated in; one set of response headers
# per file is the protocol's cost rather than the route's, and `transferSize` would add it.
TRANSFERRED = """
() => {
  const navigation = performance.getEntriesByType('navigation')[0];
  const code = performance.getEntriesByType('resource').filter(
    (entry) => /\\.(js|css)$/.test(new URL(entry.name).pathname)
  );
  const each = [['the page itself', navigation.encodedBodySize]].concat(
    code.map((entry) => [new URL(entry.name).pathname, entry.encodedBodySize])
  );
  each.sort((left, right) => right[1] - left[1]);
  return {
    bytes: each.reduce((total, [, size]) => total + size, 0),
    each: each,
  };
}
"""


@pytest.fixture
def proxied_gateway(db, runtime):
    """The console as the hosted deployment serves it: the same application, compressed."""
    if console_module.load_build() is None:
        pytest.fail("No console build is packaged: run `pnpm build` in console/ first")

    def build(origin):
        app = console_app(db, runtime, origin)
        app.add_middleware(GZipMiddleware, minimum_size=500)

        @app.middleware("http")
        async def runtime_date(request, call_next):
            response = await call_next(request)
            # The console corrects its clock from this header. Waiting for a quiet machine
            # can outlast the approval, so it must describe the same frozen time as the API.
            response.headers["Date"] = format_datetime(runtime.clock.now(), usegmt=True)
            return response

        return app

    # Avoid adding Uvicorn's real wall-clock Date alongside the fixture's Date.
    with serve(build, date_header=False) as origin:
        yield origin


@pytest.fixture
def agent(proxied_gateway, seeded):
    with httpx.Client(
        base_url=proxied_gateway,
        headers={"Authorization": "Bearer " + seeded["tokens"][0]},
        trust_env=False,
    ) as client:
        yield client


def test_proxy_date_tracks_runtime_time_even_when_wall_time_has_moved_on(agent, world):
    world["clock"].value -= timedelta(minutes=5)
    response = agent.get("/health/live")
    assert response.status_code == 200
    assert response.headers.get_list("Date") == [format_datetime(world["clock"].now(), usegmt=True)]


def signed_in(chromium, origin, admin_engine, human):
    """A fresh session for `human`, made in a browser context of its own: its storage state."""
    with chromium.new_context(base_url=origin, viewport=PHONE) as context:
        page = context.new_page()
        page.set_default_timeout(15_000)
        sign_in_as(page, admin_engine, human)
        return context.storage_state()


def cold_load(chromium, origin, sign_in, approval_id, target, alone):
    """One approval link followed on a cold phone: the seconds, the bytes, and the machine.

    `alone` holds the machine's timing lock around the measurement and waits for the box to
    go quiet first, so the seconds are this phone's and not those of other suites sharing
    it; what it says about the load travels back with the attempt, because a phone
    throttled to a quarter of a core compounds with whatever else the host is doing.

    The phone is signed in only once the lock is held, a moment before the link is followed.
    The session cookie's lifetime runs on the browser's clock while the session's own runs on
    the test's frozen one, and the waits for a quiet machine and for the lock can outlast
    it: a session made before them reached the third attempt signed out, at the sign-in
    form. Signing in is a few seconds in a context of its own, outside the measured seconds.
    """
    with chromium.new_context(base_url=origin, viewport=PHONE) as context:
        page = context.new_page()
        # Longer than the target, so a slow load is a number this test reports rather than a
        # timeout that says only that something took too long.
        page.set_default_timeout(30_000)
        session = context.new_cdp_session(page)
        session.send("Network.enable")
        session.send("Network.clearBrowserCache")
        session.send("Network.emulateNetworkConditions", FAST_4G)
        session.send("Emulation.setCPUThrottlingRate", {"rate": CPU_SLOWDOWN})
        with alone("the cold approval link on a phone") as machine:
            context.add_cookies(sign_in()["cookies"])
            started = time.monotonic()
            page.goto(f"/approvals/{approval_id}", wait_until="commit")
            expect(page.get_by_role("heading", level=2, name=target)).to_be_visible()
            approve = page.get_by_role("button", name="Approve")
            refuse = page.get_by_role("button", name="Refuse")
            expect(approve).to_be_enabled()
            expect(refuse).to_be_enabled()
            seconds = time.monotonic() - started
        session.send("Emulation.setCPUThrottlingRate", {"rate": 1})
        session.send(
            "Network.emulateNetworkConditions",
            {"offline": False, "downloadThroughput": -1, "uploadThroughput": -1, "latency": 0},
        )
        loaded = page.evaluate(TRANSFERRED)
        return seconds, loaded, machine


@pytest.mark.timed
def test_a_cold_approval_link_is_decidable_on_a_slow_phone_inside_its_budget(
    chromium, proxied_gateway, admin_engine, world, agent, live_provider, timed_alone
):
    approval = agent.post("/v1/execute", json=request(world).model_dump(mode="json")).json()
    assert approval["state"] == "PENDING_APPROVAL"
    sign_in = functools.partial(signed_in, chromium, proxied_gateway, admin_engine, world["human"])
    loads = [
        cold_load(
            chromium, proxied_gateway, sign_in, approval["approval_id"], "device-01", timed_alone
        )
        for _ in range(ATTEMPTS)
    ]
    best, _, machine = min(loads, key=lambda load: load[0])
    waited = ", ".join(f"{seconds:.2f} s" for seconds, _, _ in loads)
    assert best <= TARGET_SECONDS, (
        f"the target and both buttons took {best:.2f} s on a Fast 4G phone at "
        f"{CPU_SLOWDOWN} times CPU slowdown, over the {TARGET_SECONDS} s the approval link is "
        f"given (attempts: {waited}). The best attempt's {machine.note}"
    )


@contextlib.contextmanager
def counted_only(what):
    """No timing lock and no wait for a quiet machine: only the bytes are read."""
    yield Machine(0.0, 1, True, f"{what} counted bytes only")


def test_a_cold_approval_link_fetches_no_more_than_its_budget(
    chromium, proxied_gateway, admin_engine, world, agent, live_provider
):
    """The same cold load as the phone's, counting the document, scripts and stylesheets it
    fetched against the 160 KB an approval link opened cold is given. Untimed, so a run that
    deselects `timed` still checks the budget."""
    approval = agent.post("/v1/execute", json=request(world).model_dump(mode="json")).json()
    assert approval["state"] == "PENDING_APPROVAL"
    sign_in = functools.partial(signed_in, chromium, proxied_gateway, admin_engine, world["human"])
    _, loaded, _ = cold_load(
        chromium, proxied_gateway, sign_in, approval["approval_id"], "device-01", counted_only
    )
    largest = ", ".join(f"{name} {size / 1024:.1f} KB" for name, size in loaded["each"][:5])
    assert loaded["bytes"] <= BUDGET_BYTES, (
        f"the approval route fetched {loaded['bytes'] / 1024:.1f} KB over "
        f"{len(loaded['each'])} files, past the {BUDGET_BYTES / 1024:.0f} KB an approval link "
        f"opened cold is given. Largest: {largest}"
    )


def test_a_cold_load_is_signed_in_however_long_it_waited_for_the_machine(
    chromium, proxied_gateway, admin_engine, world, agent, live_provider, monkeypatch
):
    """A wait for the machine longer than a session lasts still ends in a signed-in load.

    The session cookie's lifetime is counted on the browser's clock and the session's own on
    the test's frozen one, so only the cookie runs out. The quiet wait and the lock queue
    together have passed the fifteen minutes a session lasts, and the third load then
    arrived signed out at the sign-in form. Here the session lasts thirty seconds and the
    wait outlasts it.
    """
    lifetime = 30
    monkeypatch.setattr(sessions, "SESSION_LIFETIME", timedelta(seconds=lifetime))
    approval = agent.post("/v1/execute", json=request(world).model_dump(mode="json")).json()
    assert approval["state"] == "PENDING_APPROVAL"
    sign_in = functools.partial(signed_in, chromium, proxied_gateway, admin_engine, world["human"])

    @contextlib.contextmanager
    def outlasted(what):
        time.sleep(lifetime + 2)
        yield Machine(0.0, 1, True, f"{what} waited longer than a session lasts")

    seconds, loaded, machine = cold_load(
        chromium, proxied_gateway, sign_in, approval["approval_id"], "device-01", outlasted
    )
    assert seconds > 0 and loaded["bytes"] > 0, (seconds, loaded, machine.note)
