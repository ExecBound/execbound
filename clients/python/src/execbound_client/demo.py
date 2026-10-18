# SPDX-License-Identifier: Apache-2.0
"""``execbound-demo``: the demo beats, run from a private directory on your machine.

    export EXECBOUND_URL=https://app.execbound.ai
    execbound-demo --private ~/execbound-demo boundary
    execbound-demo --private ~/execbound-demo decide --wait 600
    execbound-demo --private ~/execbound-demo budget

The private directory holds ``sandbox.json`` (a compatibility filename for the demo
configuration, downloaded from the console, plus a ``credentials`` object you add) and the
agent API key files it names; the gateway origin comes from ``EXECBOUND_URL`` or that file.
Make the directory yours alone (``chmod 700``) and each key file too (``chmod 600``): a key
issued for sample targets outlives the demo. Nothing sensitive is accepted on the command line
and no credential is ever printed. Each run writes ``<private>/demo-record.json`` (execution
ids and states, never tokens).

It runs against one of two kinds of workspace, which the file's ``workspace`` field names:

    samples   a Community workspace that has added its sample targets. Download the file
              from the Sample targets card on Getting started ("Download demo
              configuration"), which offers it while the starter policy decides the
              samples. ``boundary`` and ``decide`` run; ``budget`` cannot, because
              the samples hold one target the starter policy lets an agent isolate and its
              shared tenant total is twenty, so ``all`` runs the other two and says so.
              Both send as one agent, so the file needs only that agent's API key, as
              ``agent_a``; it may name ``agent_b`` too, which nothing sends. Requests carry
              no ``synthetic_demo`` mark, and the file may name only sample hostnames
              (``*.sample.invalid``) and no admin key file. The beats need the samples as
              their facts record them, and an isolation of one that executes, in a run of
              this command or by your own agent in guided setup, changes it: the card
              offers the file only while none has since the facts were recorded and the
              facts are current (an hour, on the starter policy), and says to refresh them
              otherwise, so refresh the sample facts and download the file again before
              each run after the first. The approval goes to the
              administrator who added or last refreshed the samples.
    fixtures  an isolated workspace holding only synthetic fixtures, such as a hosted
              sandbox, whose file names no ``workspace``. All three beats run, with two agents'
              API keys, ``agent_a`` and ``agent_b``, every request marked ``synthetic_demo``,
              which the gateway refuses anywhere else.

Beats:

    boundary  the agent credential opens the agent routes and nothing else: no human
              session, no provider call (scenario 1)
    decide    workstation ALLOW, domain controller DENY, a claim the inventory does not hold
              refused before any decision, production REQUIRE_APPROVAL decided from a phone,
              the agent's retry executes exactly once, and the agent's own attempt to approve
              is refused (scenarios 2, 3 and 5)
    budget    the same isolation split across two credentials over HTTP and MCP until the
              shared tenant budget refuses (scenario 4); needs the ``mcp`` extra and a
              fixture workspace
    all       the beats the workspace can carry, in order, stopping at the first that fails

``sandbox.json``::

    {
      "workspace": "samples",
      "origin": "https://app.execbound.ai",
      "tenant_id": "<uuid>",
      "credentials": {"agent_a": "agent-a.token"},
      "providers": {"endpoint": "https://<endpoint mock origin>"},
      "targets": {
        "workstation": {"kind": "hostname", "value": "ws-dev-01.sample.invalid",
                        "incident_id": "<uuid>"},
        "domain_controller": {...}, "production": {...},
        "pool": []
      }
    }

``providers`` is optional, and names a loopback address only beside a gateway whose own origin
is one: the boundary beat sends agent A's key to each origin it names. The console's samples
download names no mock at a loopback address, which the gateway cannot know this machine
reaches; add one only where it does, since an origin this machine cannot reach fails the
boundary beat. A fixture configuration names no ``workspace``, names ``"agent_b":
"agent-b.token"`` beside agent A in ``credentials``, may name targets of any kind, and may name
an ``admin`` file there too, which this command accepts and never uses; its pool needs enough
development targets to reach the tenant total (twenty on the SOC pack, minus the two
isolations of the decide beat) with both credentials still inside their autonomous budgets.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import os
import re
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit
from uuid import UUID

import httpx

from ._core import (
    PENDING_STATES,
    ExecBoundError,
    ExecBoundUncertain,
    action_request,
    intent_key,
)
from .sync import ExecBoundClient

ACTION = "endpoint.isolate"
BEATS = ("boundary", "decide", "budget")
TITLES = {
    "boundary": "the agent credential opens the agent routes and nothing else",
    "decide": "workstation allowed, domain controller denied, a false claim refused, "
    "production decided by a human",
    "budget": "two credentials, two transports, one tenant budget",
}
CREDENTIALS = ("agent_a", "agent_b", "admin")
WORKSPACES = ("fixtures", "samples")
# The only targets a samples configuration may name: the sample hostnames the workspace's
# samples carry, which no real system answers to (RFC 2606 reserves `.invalid`).
SAMPLE_HOSTNAME = re.compile(r"[a-z0-9-]{1,40}\.sample\.invalid")
TOKEN = re.compile(r"[!-~]{1,512}")
LOGIN_CSRF = re.compile(r'name="csrf"[^>]*value="([A-Za-z0-9_-]{43})"')
# Why the budget beat does not run on samples, said wherever it is skipped or refused.
SAMPLES_BUDGET = (
    "a workspace's samples hold one target the starter policy lets an agent isolate, and its "
    "shared tenant total is twenty isolations in fifteen minutes"
)
# What to do when the samples' facts no longer match what the demo configuration names, or have
# gone stale, which refuses every request on them before any decision. The card stops offering
# the file while the samples cannot carry the demo, which a refresh does not change where a
# policy of the person's own decides them in the starter's place.
SAMPLES_REFRESH = (
    "refresh the sample facts on Getting started and download the demo configuration again, "
    "which the Sample targets card offers only while the starter policy decides the samples, "
    "their facts are current and no request has isolated them since the facts were recorded"
)
# Why an isolation the decide beat expects to execute ended STALE_AUTHORIZATION, on samples:
# the provider found the target past the version the facts record, which an executed isolation
# of it since then does, a run of this command's or the person's own agent's in guided setup,
# and nothing says which one it was.
SAMPLES_USED = (
    "the demo needs the sample targets as their facts record them, and a request, a run of "
    "this command's or your own agent's, has isolated one since their facts were recorded"
)


def samples_outcome(what: str, state: str) -> str:
    """Why an isolation on samples the decide beat expects to execute ended otherwise, and what
    to do: only a target found past its recorded version is one a refresh helps with."""
    if state == "STALE_AUTHORIZATION":
        return f"{what} ended {state}, not EXECUTED: {SAMPLES_USED}; {SAMPLES_REFRESH}"
    return f"{what} ended {state}, not EXECUTED; the console's Activity page shows what happened"


def refusal_advice(what: str, status: int, code: str, *, samples: bool) -> str:
    """Why a request the decide beat expects to be decided was refused instead, by the code the
    gateway answered with, and what to do. Only `EXECUTION_UNAVAILABLE` is one the facts cause,
    stale or no longer naming the target, and so the only one a refresh of them and a new
    download mend. An agent key the gateway no longer accepts, an emergency stop and an agent
    whose space has no policy refuse every request alike, whatever the facts say."""
    said = f"{what} was refused ({status} {code})"
    if code == "EXECUTION_UNAVAILABLE":
        if samples:
            return f"{said}; {SAMPLES_REFRESH}"
        return (
            f"{said}; the workspace's fixture facts have gone stale or no longer name the target; "
            "record them again and check that every target's incident is open"
        )
    if status == 401:
        return (
            f"{said}: the gateway does not accept agent A's API key, which may have expired or "
            "been revoked; issue a new one and save it in the file sandbox.json names"
        )
    if code == "TENANT_STOPPED":
        return (
            f"{said}: the workspace is under an emergency stop, which refuses every new request "
            "until an administrator lifts it"
        )
    if code == "NO_ACTIVE_BUNDLE":
        return f"{said}: the agent's space has no active policy" + (
            "; the starter policy decides the samples for the default space, so use the API key "
            "of an agent in the default space"
            if samples
            else "; an administrator activates one"
        )
    return f"{said}; the Errors section of the agent API reference says what the code means"


Runner = Callable[[dict[str, Any]], None]


class SandboxError(Exception):
    pass


def loopback(origin: str) -> bool:
    """Whether an origin names the machine it is read on: a loopback IP address, or
    `localhost` and its subdomains."""
    host = (urlsplit(origin).hostname or "").lower()
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class BeatFailed(Exception):
    pass


@dataclass(frozen=True)
class Target:
    kind: str
    value: str
    incident_id: str

    @classmethod
    def parse(cls, raw: Any, where: str) -> Target:
        if not isinstance(raw, dict) or set(raw) != {"kind", "value", "incident_id"}:
            raise SandboxError(f"{where}: a target needs kind, value and incident_id")
        if not all(isinstance(raw[key], str) and raw[key] for key in raw):
            raise SandboxError(f"{where}: target fields must be non-empty strings")
        return cls(raw["kind"], raw["value"], raw["incident_id"])


@dataclass(frozen=True)
class Sandbox:
    directory: Path
    origin: str
    tenant_id: str
    tokens: Mapping[str, str]
    credential_files: Mapping[str, Path]
    providers: Mapping[str, str]
    targets: Mapping[str, Target]
    pool: tuple[Target, ...]
    bundle: Path | None
    candidate: Path | None
    # "samples" for a Community workspace's sample targets, read from the console's download;
    # "fixtures" for an isolated synthetic-fixture workspace, and for a file that names none.
    workspace: Literal["fixtures", "samples"] = "fixtures"

    @property
    def synthetic(self) -> bool:
        """Whether requests carry `synthetic_demo`, which a gateway refuses outside a workspace
        holding only synthetic fixtures; a samples workspace is not one."""
        return self.workspace == "fixtures"

    @classmethod
    def load(
        cls, directory: Path, environ: Mapping[str, str], *, require_admin: bool = False
    ) -> Sandbox:
        path = directory / "sandbox.json"
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise SandboxError(f"cannot read {path}: {type(exc).__name__}") from None
        if not isinstance(document, dict):
            raise SandboxError("sandbox.json must hold an object")
        workspace = document.get("workspace", "fixtures")
        if workspace not in WORKSPACES:
            raise SandboxError("workspace must be fixtures or samples")
        samples = workspace == "samples"
        origin = str(environ.get("EXECBOUND_URL") or document.get("origin") or "").rstrip("/")
        if not re.fullmatch(r"https?://[^\s/]+", origin):
            raise SandboxError("origin must be an http(s) origin (EXECBOUND_URL or sandbox.json)")
        try:
            tenant_id = str(UUID(str(document.get("tenant_id"))))
        except ValueError:
            raise SandboxError("tenant_id must be a UUID") from None
        credentials = document.get("credentials")
        if samples and (
            require_admin or (isinstance(credentials, dict) and "admin" in credentials)
        ):
            raise SandboxError(
                "a samples configuration names an agent's key file and no admin file"
            )
        if samples:
            # The beats samples carry send as agent A alone; `budget`, the one that uses agent
            # B, never runs on them, so a second key is accepted but never needed or sent.
            if not isinstance(credentials, dict) or not (
                {"agent_a"} <= set(credentials) <= {"agent_a", "agent_b"}
            ):
                raise SandboxError("credentials must name an agent_a file")
        else:
            wanted = {"agent_a", "agent_b"} | ({"admin"} if require_admin else set())
            if not isinstance(credentials, dict) or not (
                wanted <= set(credentials) <= set(CREDENTIALS)
            ):
                raise SandboxError(
                    "credentials must name agent_a and agent_b files"
                    + (" and an admin file" if require_admin else "")
                )
        files = {name: directory / str(file) for name, file in credentials.items()}
        tokens = {}
        for name, file in files.items():
            try:
                token = file.read_text(encoding="ascii").strip()
            except (OSError, UnicodeDecodeError):
                raise SandboxError(f"credential file for {name} is unreadable") from None
            if not TOKEN.fullmatch(token):
                raise SandboxError(f"credential file for {name} does not hold one token")
            tokens[name] = token
        providers = document.get("providers") or {}
        if not isinstance(providers, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in providers.items()
        ):
            raise SandboxError("providers must map a label to an origin")
        # The boundary beat sends agent A's key to every origin named here. A loopback one is
        # the gateway's own mock only beside a gateway on this machine's loopback; beside one
        # published elsewhere it is whatever listens on that port here.
        if not loopback(origin) and any(loopback(str(v)) for v in providers.values()):
            raise SandboxError(
                "providers may name a loopback address only when the gateway's origin is one"
            )
        raw_targets = document.get("targets")
        if not isinstance(raw_targets, dict) or set(raw_targets) != {
            "workstation",
            "domain_controller",
            "production",
            "pool",
        }:
            raise SandboxError(
                "targets must name workstation, domain_controller, production and pool"
            )
        targets = {
            name: Target.parse(raw_targets[name], f"targets.{name}")
            for name in ("workstation", "domain_controller", "production")
        }
        if not isinstance(raw_targets["pool"], list) or not (samples or raw_targets["pool"]):
            raise SandboxError(
                "targets.pool must be a list"
                if samples
                else "targets.pool must be a non-empty list"
            )
        pool = tuple(
            Target.parse(item, f"targets.pool[{index}]")
            for index, item in enumerate(raw_targets["pool"])
        )
        if samples:
            # Requests on samples carry no `synthetic_demo` mark, so this is what keeps them on
            # the sample targets: anything else would be a request on a real system.
            named = [*((f"targets.{name}", t) for name, t in targets.items())]
            named += [(f"targets.pool[{index}]", t) for index, t in enumerate(pool)]
            for where, target in named:
                if target.kind != "hostname":
                    raise SandboxError(f"{where}: a sample target is named by hostname")
                if not SAMPLE_HOSTNAME.fullmatch(target.value):
                    raise SandboxError(f"{where}: a sample target's hostname ends .sample.invalid")
        bundle = directory / str(document["bundle"]) if document.get("bundle") else None
        candidate = directory / "candidate-bundle.json"
        return cls(
            directory=directory,
            origin=origin,
            tenant_id=tenant_id,
            tokens=tokens,
            credential_files=files,
            providers={str(k): str(v).rstrip("/") for k, v in providers.items()},
            targets=targets,
            pool=pool,
            bundle=bundle,
            candidate=candidate if candidate.exists() else None,
            workspace="samples" if samples else "fixtures",
        )


class DemoClient(ExecBoundClient):
    """Mark every attempt, including retries made from a previously saved configuration."""

    def execute(self, request: dict[str, Any]) -> dict[str, Any]:
        return super().execute({**request, "synthetic_demo": True})


class Record:
    """What a run produced: identifiers and states, never credentials."""

    def __init__(self, path: Path, run: str, tenant_id: str) -> None:
        self.path = path
        self.data: dict[str, Any] = {
            "run": run,
            "tenant_id": tenant_id,
            "started_at": datetime.now(UTC).isoformat(),
            "beats": [],
        }
        if path.exists():
            try:
                previous = json.loads(path.read_text(encoding="utf-8"))
            except ValueError:
                previous = None
            if isinstance(previous, dict) and previous.get("run") == run:
                self.data = previous

    def beat(self, name: str) -> dict[str, Any]:
        entry: dict[str, Any] = {"beat": name, "started_at": datetime.now(UTC).isoformat()}
        entry["steps"] = []
        self.data["beats"] = [b for b in self.data["beats"] if b.get("beat") != name]
        self.data["beats"].append(entry)
        return entry

    def save(self) -> None:
        self.path.write_text(json.dumps(self.data, indent=1, default=str), encoding="utf-8")


def clean(view: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in view.items() if key != "continuation"}


class Driver:
    def __init__(
        self,
        sandbox: Sandbox,
        record: Record,
        *,
        run: str,
        sleep: Callable[[float], None] = time.sleep,
        out: Callable[[str], None] = print,
        timeout: float = 30.0,
    ) -> None:
        self.sandbox = sandbox
        self.record = record
        self.run = run
        self.sleep = sleep
        self.out = out
        client = DemoClient if sandbox.synthetic else ExecBoundClient
        self.clients = {
            name: client(sandbox.origin, token, timeout=timeout)
            for name, token in sandbox.tokens.items()
            if name != "admin"
        }
        self.raw = httpx.Client(
            timeout=timeout,
            trust_env=False,
            headers={"Authorization": "Bearer " + sandbox.tokens["agent_a"]},
        )

    def close(self) -> None:
        for client in self.clients.values():
            client.close()
        self.raw.close()

    def runners(self, *, wait: float, poll: float, unattended: bool = False) -> dict[str, Runner]:
        """The beat callables this driver offers, in the order they are meant to run."""
        return {
            "boundary": self.boundary,
            "decide": partial(self.decide, wait=wait, poll=poll, unattended=unattended),
            "budget": self.budget,
        }

    # Requests and keys

    def key(self, beat: str, target: Target, attempt: int = 1) -> str:
        return intent_key(ACTION, target.kind, target.value, f"{self.run}/{beat}/{attempt}")

    def request(self, beat: str, target: Target, attempt: int = 1) -> dict[str, Any]:
        return action_request(
            ACTION,
            target.kind,
            target.value,
            self.key(beat, target, attempt),
            incident_id=target.incident_id,
        )

    def show(self, steps: list[dict[str, Any]], label: str, view: Mapping[str, Any]) -> None:
        entry = {"label": label, **clean(view)}
        steps.append(entry)
        summary = f"state={view.get('state')} execution={view.get('execution_id')}"
        if view.get("approval_state"):
            summary += f" approval={view['approval_state']}"
        self.out(f"  {label}: {summary}")

    def refused(self, steps: list[dict[str, Any]], label: str, exc: ExecBoundError) -> None:
        steps.append({"label": label, "refused": exc.code, "status": exc.status})
        self.out(f"  {label}: refused status={exc.status} code={exc.code}")

    def send(
        self,
        agent: str,
        steps: list[dict[str, Any]],
        label: str,
        request: dict[str, Any],
        *,
        wait: float = 0.0,
        poll: float = 3.0,
    ) -> dict[str, Any] | None:
        """Send over HTTP and wait for a decision when asked; None when refused."""
        try:
            outcome = self.clients[agent].run_to_completion(
                request, approval_wait_seconds=wait, poll_seconds=poll, sleep=self.sleep
            )
        except ExecBoundUncertain as uncertain:
            self.show(steps, label + " (UNCERTAIN, reconcile before any retry)", uncertain.view)
            return uncertain.view
        except ExecBoundError as exc:
            self.refused(steps, label, exc)
            return None
        self.show(steps, label, outcome.view)
        return outcome.view

    def send_mcp(
        self, agent: str, steps: list[dict[str, Any]], label: str, request: dict[str, Any]
    ) -> dict[str, Any] | None:
        try:
            from . import mcp as transport
        except ImportError:
            raise BeatFailed(
                'the MCP half of this beat needs the mcp extra: pip install "execbound-client[mcp]"'
            ) from None
        try:
            view = asyncio.run(
                transport.run_action(
                    self.sandbox.origin,
                    self.sandbox.tokens[agent],
                    {**request, "synthetic_demo": True} if self.sandbox.synthetic else request,
                    approval_wait_seconds=0,
                )
            )
        except transport.McpRefused as exc:
            steps.append({"label": label, "refused": exc.code, "tool": exc.tool})
            self.out(f"  {label}: refused by MCP tool {exc.tool} code={exc.code}")
            return None
        self.show(steps, label, view)
        return view

    def unreachable(
        self,
        steps: list[dict[str, Any]],
        label: str,
        party: str,
        exc: httpx.TransportError,
        advice: str = "",
    ) -> BeatFailed:
        """A request that reached nothing, recorded as such, and the beat's failure saying who
        this machine could not reach: an origin in the file may be one only the gateway
        reaches, and a request that reached nothing proves nothing about what the credential
        opens."""
        reason = type(exc).__name__
        steps.append({"label": label, "unreachable": reason})
        self.out(f"  {label}: unreachable ({reason})")
        said = f"{party} could not be reached from this machine ({reason})"
        return BeatFailed(f"{said}; {advice}" if advice else said)

    def probe(
        self,
        steps: list[dict[str, Any]],
        label: str,
        method: str,
        url: str,
        *,
        party: str | None = None,
        advice: str = "",
        **options: Any,
    ) -> httpx.Response:
        try:
            response = self.raw.request(method, url, follow_redirects=False, **options)
        except httpx.TransportError as exc:
            where = party or f"the gateway at {self.sandbox.origin}"
            raise self.unreachable(steps, label, where, exc, advice) from None
        steps.append({"label": label, "status": response.status_code})
        self.out(f"  {label}: {response.status_code}")
        return response

    # Beats

    def boundary(self, beat: dict[str, Any]) -> None:
        steps, origin = beat["steps"], self.sandbox.origin
        me = self.probe(steps, "GET /v1/me", "GET", origin + "/v1/me")
        if me.status_code != 200:
            raise BeatFailed("the gateway does not accept the agent credential")
        identity = me.json()
        steps[-1]["kind"] = identity.get("kind")
        steps[-1]["principal_id"] = identity.get("principal_id")
        self.out(
            f"    identity kind={identity.get('kind')} principal={identity.get('principal_id')}"
        )
        for path in ("/v1/config", "/v1/connectors", "/approvals", "/activity", "/policy"):
            response = self.probe(steps, "GET " + path, "GET", origin + path)
            if response.status_code == 200:
                raise BeatFailed(f"the agent credential opened {path}")
        # A person pasting the agent credential into the sign-in form: no bearer header,
        # the page's own CSRF token and cookie, the browser's Origin.
        label = "POST /session with the agent credential"
        with httpx.Client(timeout=30.0, trust_env=False) as browser:
            try:
                login = browser.get(origin + "/login")
                match = LOGIN_CSRF.search(login.text) if login.status_code == 200 else None
                form = {
                    "credential": self.sandbox.tokens["agent_a"],
                    "csrf": match[1] if match else "",
                }
                session = browser.post(
                    origin + "/session",
                    data=form,
                    headers={"Origin": origin},
                    follow_redirects=False,
                )
            except httpx.TransportError as exc:
                raise self.unreachable(steps, label, f"the gateway at {origin}", exc) from None
        steps.append({"label": label, "status": session.status_code})
        self.out(f"  {label}: {session.status_code}")
        if session.status_code < 400:
            raise BeatFailed("the agent credential opened a human session")
        for label, provider in self.sandbox.providers.items():
            response = self.probe(
                steps,
                f"{label} POST /v1/contain",
                "POST",
                provider + "/v1/contain",
                party=f"the {label} provider at {provider}",
                advice="name a mock under providers only where this machine reaches it, or "
                "leave providers out of sandbox.json to check the gateway alone",
                content=b"{}",
                headers={"Content-Type": "application/json"},
            )
            if response.status_code < 400:
                raise BeatFailed(f"{label} accepted the agent credential")

    def decide(
        self, beat: dict[str, Any], *, wait: float, poll: float, unattended: bool = False
    ) -> None:
        """The approval beat.

        `unattended` exists for the public showcase, which runs this hourly with no
        approver credential ever issued: it sends the production request once, records
        that it is pending and who could answer it, and returns. Every held request then
        expires, which is the honest story that board tells each hour — a request nobody
        answered is not a failure of the demonstration, it is the demonstration.

        It changes nothing for a person running the demo, and `boundary` and `budget` do
        not know about it at all.
        """
        steps, targets = beat["steps"], self.sandbox.targets
        samples = not self.sandbox.synthetic
        workstation = self.request("decide", targets["workstation"])
        view = self.send("agent_a", steps, "workstation isolate", workstation)
        if view is None:
            # `send` has just recorded the refusal's status and code as the last step.
            raise BeatFailed(
                refusal_advice(
                    "the workstation isolation",
                    steps[-1]["status"],
                    steps[-1]["refused"],
                    samples=samples,
                )
            )
        if view["state"] != "EXECUTED":
            raise BeatFailed(
                samples_outcome("the workstation isolation", view["state"])
                if samples
                else f"the workstation isolation ended {view['state']}, not EXECUTED "
                "(a STALE_AUTHORIZATION here means the registry does not know the target's "
                "current provider version)"
            )
        again = self.send("agent_a", steps, "workstation isolate, same key", workstation)
        if again is None or again["execution_id"] != view["execution_id"]:
            raise BeatFailed("the same key did not return the same execution")
        denied = self.send(
            "agent_a",
            steps,
            "domain controller isolate",
            self.request("decide", targets["domain_controller"]),
        )
        if denied is None or denied["state"] != "DENIED":
            raise BeatFailed("the domain controller isolation was not denied")
        self.out("    the reason is on the Activity page and in the export, never in the view")

        # A claim the trusted inventory does not hold on the target: the incident of the
        # domain controller named against a development workstation, from the pool, or the
        # demo's own workstation where there is none, as on samples. The gateway finds no
        # incident fact for that target, so admission refuses before any policy decision. Its
        # key is its own: the incident is no part of a request's identity, so under the
        # workstation's key the claim would only bring back that isolation.
        claimed = self.sandbox.pool[0] if self.sandbox.pool else targets["workstation"]
        lie = Target(claimed.kind, claimed.value, targets["domain_controller"].incident_id)
        label = f"{lie.value} isolate, claiming the domain controller's incident"
        if self.send("agent_a", steps, label, self.request("decide-claim", lie)) is not None:
            raise BeatFailed("a claim the inventory does not hold on the target was not refused")
        if steps[-1].get("refused") != "EXECUTION_UNAVAILABLE":
            raise BeatFailed(
                f"the claim was refused as {steps[-1].get('refused')}, not as unavailable context"
            )
        self.out(
            "    refused before any decision: the claim selected an incident the inventory "
            "does not hold on that target, so there was nothing to decide with"
        )

        attempt = 1
        production = self.request("decide", targets["production"], attempt)
        try:
            first = self.clients["agent_a"].execute(production)
        except ExecBoundError as exc:
            self.refused(steps, "production isolate", exc)
            raise BeatFailed("the production isolation was refused") from None
        self.show(steps, "production isolate", first)
        if first["state"] != "PENDING_APPROVAL":
            raise BeatFailed(
                f"the production isolation did not require approval ({first['state']})"
            )
        approval_url = first.get("approval_url") or self.sandbox.origin + "/approvals"
        self.out(f"    approve it on a phone at {approval_url}")
        if samples:
            self.out(
                "    review of the samples is the administrator's who added or last refreshed "
                "them, so sign in as that person"
            )
        decide_url = f"{self.sandbox.origin}/approvals/{first['approval_id']}/decide"
        attempt_to_approve = self.probe(
            steps,
            "agent tries to approve",
            "POST",
            decide_url,
            data={"decision": "APPROVE"},
            headers={"Origin": self.sandbox.origin},
        )
        if attempt_to_approve.status_code < 400:
            raise BeatFailed("the agent credential reached the approval decision")
        if unattended:
            # Everything above this line is the part that needs nobody. The request is
            # pending and the approval id is recorded; nothing waits and nothing expires
            # early. Whoever reads the run later sees exactly where it stopped and why.
            beat["pending"] = {
                "execution_id": first["execution_id"],
                "approval_id": first["approval_id"],
                "state": first["state"],
            }
            self.out(
                f"    left pending as {first['state']}: approval {first['approval_id']} "
                "has nobody to answer it, and will expire at its deadline"
            )
            return
        self.out(f"    waiting up to {wait:.0f}s for the human decision")
        deadline = time.monotonic() + wait
        final = None
        while final is None:
            remaining = max(0.0, deadline - time.monotonic())
            view = self.send(
                "agent_a",
                steps,
                "production isolate, after the decision",
                production,
                wait=remaining,
                poll=poll,
            )
            if view is None:
                raise BeatFailed("the production isolation was refused while waiting")
            if view["state"] == "STALE_AUTHORIZATION" and view.get("approval_state") == "EXPIRED":
                if attempt >= 3 or time.monotonic() >= deadline:
                    raise BeatFailed("the approval expired; nobody decided within the deadline")
                attempt += 1
                self.out("    the approval expired; requesting again under a new key")
                production = self.request("decide", targets["production"], attempt)
                continue
            if view["state"] in PENDING_STATES:
                raise BeatFailed(f"no decision within {wait:.0f} seconds")
            final = view
        if final["state"] != "EXECUTED":
            raise BeatFailed(
                samples_outcome("the production isolation", final["state"])
                if samples
                else f"the production isolation ended {final['state']}"
            )
        same = self.send("agent_a", steps, "production isolate, same key", production)
        if same is None or same["execution_id"] != final["execution_id"]:
            raise BeatFailed("the retry did not return the executed intent")
        self.out("    executed exactly once; the same key returns the same execution")

    def budget(self, beat: dict[str, Any]) -> None:
        if not self.sandbox.synthetic:
            # Refused before anything is sent: no run of it on samples could reach the total.
            raise BeatFailed(f"this beat needs a synthetic-fixture workspace: {SAMPLES_BUDGET}")
        steps = beat["steps"]
        transports = (("http", "agent_a"), ("mcp", "agent_b"))
        executed = {"http": 0, "mcp": 0}
        stale = {"http": 0, "mcp": 0}
        escalated: list[str] = []
        denied = None
        for index, target in enumerate(self.sandbox.pool):
            transport, agent = transports[index % 2]
            if transport in escalated:
                transport, agent = transports[(index + 1) % 2]
                if transport in escalated:
                    break
            request = self.request("budget", target)
            label = f"pool[{index}] {target.value} via {transport} ({agent})"
            if transport == "http":
                view = self.send(agent, steps, label, request)
            else:
                view = self.send_mcp(agent, steps, label, request)
            if view is None:
                continue
            steps[-1]["transport"] = transport
            state = view["state"]
            if state == "EXECUTED":
                executed[transport] += 1
            elif state in PENDING_STATES:
                escalated.append(transport)
                self.out(f"    {transport}: the credential's own budget escalated to a human")
            elif state == "DENIED":
                denied = {"index": index, "transport": transport, **clean(view)}
                break
            elif state == "STALE_AUTHORIZATION":
                stale[transport] += 1
        beat["executed"], beat["escalated"], beat["stale"], beat["denied"] = (
            executed,
            escalated,
            stale,
            denied,
        )
        self.out(
            f"    executed over HTTP: {executed['http']}, over MCP: {executed['mcp']}; "
            f"escalated: {escalated or 'none'}"
        )
        if denied is None:
            raise BeatFailed(
                "the tenant budget did not refuse; the pool is too small or the windows moved"
            )
        self.out("    the tenant total refused the next isolation on either transport")


def run_beats(
    driver: Driver,
    beats: Sequence[str],
    runners: Mapping[str, Runner],
    titles: Mapping[str, str],
    *,
    program: str = "execbound-demo",
) -> int:
    """Run the named beats in order, recording each; 0 when all pass, 2 at the first failure."""
    started = time.monotonic()
    order = list(titles)
    for name in beats:
        driver.out(f"== {order.index(name) + 1}. {name}: {titles[name]}")
        beat = driver.record.beat(name)
        began = time.monotonic()
        try:
            runners[name](beat)
        except BeatFailed as failure:
            beat["failed"] = str(failure)
            beat["elapsed_seconds"] = round(time.monotonic() - began, 1)
            driver.record.save()
            driver.out(f"  FAILED: {failure}")
            print(f"{program}: {name} failed: {failure}", file=sys.stderr)
            return 2
        beat["failed"] = None
        beat["elapsed_seconds"] = round(time.monotonic() - began, 1)
        driver.record.save()
        driver.out(f"  done in {beat['elapsed_seconds']}s")
    driver.out(
        f"all requested beats done in {time.monotonic() - started:.0f}s; "
        f"record at {driver.record.path}"
    )
    return 0


def main(
    argv: list[str] | None = None,
    *,
    sleep: Callable[[float], None] = time.sleep,
    environ: Mapping[str, str] | None = None,
) -> int:
    parser = argparse.ArgumentParser(
        prog="execbound-demo", description="Run the demo beats from a private directory."
    )
    parser.add_argument("--private", type=Path, required=True, help="private directory")
    parser.add_argument("--run", default=None, help="label of this take (default: timestamp)")
    parser.add_argument("--wait", type=float, default=600.0, help="seconds to wait for the human")
    parser.add_argument("--poll", type=float, default=3.0)
    parser.add_argument(
        "--unattended",
        action="store_true",
        help="leave the approval pending instead of waiting for a person to decide",
    )
    parser.add_argument("beat", choices=BEATS + ("all",))
    args = parser.parse_args(argv)
    environment = dict(environ) if environ is not None else dict(os.environ)
    try:
        sandbox = Sandbox.load(args.private, environment)
    except SandboxError as exc:
        print(f"execbound-demo: {exc}", file=sys.stderr)
        return 2
    run = args.run or datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    record = Record(args.private / "demo-record.json", run, sandbox.tenant_id)
    driver = Driver(sandbox, record, run=run, sleep=sleep)
    driver.out(f"sandbox tenant {sandbox.tenant_id} at {sandbox.origin}, run {run}")
    try:
        beats: tuple[str, ...] = BEATS if args.beat == "all" else (args.beat,)
        # On samples `all` is the two beats they carry; `budget` asked for by name says why not.
        skipped = args.beat == "all" and not sandbox.synthetic
        if skipped:
            beats = tuple(name for name in beats if name != "budget")
        runners = driver.runners(wait=args.wait, poll=args.poll, unattended=args.unattended)
        status = run_beats(driver, beats, runners, TITLES)
        if status == 0 and skipped:
            driver.out(
                f"budget needs a synthetic-fixture workspace and was not run: {SAMPLES_BUDGET}"
            )
        return status
    finally:
        driver.close()


if __name__ == "__main__":
    sys.exit(main())
