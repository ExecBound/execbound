# SPDX-License-Identifier: AGPL-3.0-only
"""Reproduce the synthetic monitoring path and retain only allowlisted UI evidence."""

import argparse
import json
import socket
import subprocess
import sys
import sysconfig
import time
import traceback
from pathlib import Path

import httpx
from playwright.sync_api import sync_playwright

from execbound.monitoring.commands import read_private


class DemoError(RuntimeError):
    """A failure this script words itself, so its message carries no private value."""


_STDLIB = Path(sysconfig.get_paths()["stdlib"]).resolve()
# The browser suite's sideways check (`FITS` in tests/test_browser_surfaces.py), written out
# because this script does not import the tests: neither the document nor `main`, which scrolls
# on its own below 768 px, so content wider than it pans there without widening the document.
FITS = """
() => {
  const root = document.documentElement;
  const main = document.querySelector('main');
  return root.scrollWidth <= root.clientWidth
    && (main === null || main.scrollWidth <= main.clientWidth);
}
"""


def _origin(failure: BaseException) -> str:
    """Where it failed, by file and line. The deepest standard library frame names the
    mechanism rather than the mistake, so the deepest frame outside it is reported."""

    def ours(frame: traceback.FrameSummary) -> bool:
        if frame.filename.startswith("<"):
            return False
        return not Path(frame.filename).resolve().is_relative_to(_STDLIB)

    frames = traceback.extract_tb(failure.__traceback__)
    named = [frame for frame in frames if ours(frame)] or frames
    return f"{Path(named[-1].filename).name}:{named[-1].lineno}"


def run(private: Path, output: Path) -> None:
    config = read_private(private)
    ports = [config["gateway_port"], config["receiver_port"]]
    if any(type(port) is not int or not 1024 <= port <= 65535 for port in ports):
        raise ValueError("Invalid demo ports")
    if ports[0] == ports[1]:
        raise ValueError("Demo ports must differ")
    for port in ports:
        with socket.socket() as probe:
            try:
                probe.bind(("127.0.0.1", port))
            except OSError:
                # Two runs on one machine, not a broken demonstration. A port number
                # names itself safely; say which one rather than leaving the reader
                # to infer a collision from how fast this exited.
                raise DemoError(f"port {port} is already in use") from None
    # After the ports, so a rerun after a collision reports the collision again
    # rather than the output directory the refused run left behind.
    output.mkdir(parents=True, exist_ok=False)
    commands = [sys.executable, "-m", "execbound.monitoring.commands"]
    children = []
    gateway = f"http://127.0.0.1:{ports[0]}"
    receiver_output = private.parent / (private.stem + "-receipts")
    try:
        for name, extra in (("serve", []), ("receiver", ["--output", str(receiver_output)])):
            children.append(
                subprocess.Popen(
                    commands + [name, "--config", str(private), *extra],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            )
        deadline = time.monotonic() + 30
        with httpx.Client(trust_env=False, timeout=1, follow_redirects=False) as client:
            while True:
                if any(child.poll() is not None for child in children):
                    raise RuntimeError("Local demo service stopped")
                try:
                    ready = client.get(gateway + "/health/ready").status_code == 200
                    receiver_ready = client.get(f"http://127.0.0.1:{ports[1]}/").status_code == 501
                    if ready and receiver_ready:
                        break
                except httpx.HTTPError:
                    pass
                if time.monotonic() >= deadline:
                    raise RuntimeError("Local demo service unavailable")
                time.sleep(0.1)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            try:
                page = browser.new_page(viewport={"width": 1440, "height": 1000})
                page.set_default_timeout(15000)
                page.goto(gateway + "/login?setup=1")
                page.locator('input[name="credential"]').fill(config["admin_token"])
                # Named exactly: the sign-in page offers a password form whose button is
                # "Sign in", and an unanchored name matches that one too.
                page.get_by_role("button", name="Continue setup", exact=True).click()
                # An administrator lands on Home, the origin's root.
                page.wait_for_url(gateway + "/")
                # The console's Monitoring page, with the view in the address (#333).
                page.goto(gateway + "/monitor?view=connections")
                page.get_by_text("No heartbeat", exact=True).wait_for()
                for arguments in (["emit-demo"], ["process", "--deliver-local"]):
                    result = subprocess.run(
                        commands + arguments + ["--config", str(private)],
                        capture_output=True,
                        timeout=30,
                        check=True,
                    )
                    if arguments[0] == "process":
                        assert json.loads(result.stdout) == {
                            "evaluated": 1,
                            "health_changes": 1,
                            "delivered": 1,
                            # This tenant has no collected agents, so the reach the worker
                            # derives from observations and settled executions is nothing,
                            # and no actor's first consequential action is raised (#355).
                            "reach": 0,
                            "actions": 0,
                            # Nor has it a directory connection, so the pass's last step finds
                            # no audit observation to purge (#355).
                            "purged": 0,
                        }
                for view in ("connections", "activity", "findings", "alerts"):
                    response = page.goto(gateway + "/monitor?view=" + view)
                    assert response is not None and response.status == 200
                    if view == "connections":
                        page.get_by_text("Reporting", exact=True).first.wait_for()
                    if view == "activity":
                        page.get_by_text("identity.disable", exact=True).first.wait_for()
                    if view == "alerts":
                        # The local test receiver is folded (#678); every delivery is listed
                        # outside it, with its destination, in every edition (#31).
                        page.get_by_text("Local test receiver", exact=True).click()
                        page.get_by_text("DELIVERED", exact=True).first.wait_for()
                    page.screenshot(path=str(output / (view + "-desktop.png")), full_page=True)
                # Findings is a queue of rows that open in place; acknowledged, the finding
                # leaves the open queue and is listed under All (#678).
                page.goto(gateway + "/monitor?view=findings")
                page.get_by_role("button", name="Show details").first.click()
                page.get_by_role("button", name="Acknowledge finding").first.click()
                page.get_by_text("Finding acknowledged.", exact=True).wait_for()
                page.get_by_role("button", name="All", exact=True).click()
                page.get_by_text("Acknowledged", exact=True).first.wait_for()
                page.set_viewport_size({"width": 390, "height": 844})
                for view in ("connections", "activity", "findings", "alerts"):
                    page.goto(gateway + "/monitor?view=" + view)
                    page.get_by_role("heading", level=1, name="Monitoring").wait_for()
                    assert page.evaluate(FITS), view
                    page.screenshot(path=str(output / (view + "-mobile.png")), full_page=True)
            finally:
                browser.close()
        receipts = list(receiver_output.glob("*.json"))
        assert len(receipts) == 1
        receipt = json.loads(receipts[0].read_text())
        assert receipt["kind"] == "monitor.finding"
        assert receipt["rule_version"] == "sensitive-action.v2"
        (output / "monitoring.json").write_text(
            json.dumps(
                {
                    "synthetic": True,
                    "vendor_requests": 0,
                    "execution_connectors": 0,
                    "observations": 1,
                    "findings": 1,
                    "receiver_receipts": 1,
                    "acknowledged": True,
                    "views_checked": 4,
                    "mobile_width": 390,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
    finally:
        for child in reversed(children):
            child.terminate()
        for child in reversed(children):
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        run(args.private, args.output)
    except DemoError as failure:
        parser.exit(1, f"Monitoring demo incomplete: {failure}.\n")
    except Exception as failure:
        # Enough to tell a port collision from a page regression, and no more: an
        # arbitrary exception's message can carry configuration, so it stays unread.
        parser.exit(
            1,
            f"Monitoring demo incomplete: {type(failure).__name__} at {_origin(failure)}; "
            "inspect local setup and isolated test results.\n",
        )
    print("Synthetic monitoring browser and local delivery demonstration passed.")
