# SPDX-License-Identifier: AGPL-3.0-only
"""The synthetic directory: a Microsoft Entra directory that exists only in this process (#355).

A workspace with no real directory connected can add one connection of kind `fixture`, labelled
"Synthetic directory", to see what Scout does before it connects its own. It holds no key and no
consent, and its shape is fixed: a base address in the reserved `.invalid` domain, which
resolves nowhere, and a directory and client no directory holds (0099's checks).

It is collected by the real Graph collector, `graph.run`, on the normal schedule, through
`client`: an `httpx.Client` over `httpx.MockTransport`, whose handler answers the token endpoint
and the Graph reads the collector makes from the fixed dataset below. That is the only seam. No
socket is opened, the token is a constant that authenticates nothing anywhere, and nothing it
reads is a real directory's. `graph.run` gives a synthetic connection this client and no other,
and gives a real connection never this one.

The dataset is reviewed data, stamped relative to the run's clock, with stable identifiers for
each day, so a later run reads the same entries again and recognises them:

- an agent identity with a blueprint and a sponsor (driver declared by its blueprint);
- a consented application with Anthropic's catalogued application id and a delegated consent
  (`consented_app`, driver declared by the AI publisher catalog);
- a classic service principal that holds the permission to disable users, signs in every day
  from Anthropic's published outbound range and disables a synthetic user every day (driver
  `network`, observed reach, "Did");
- a managed identity;
- a principal with nobody accountable, holding the permission to revoke sessions and signing in
  from a documentation address nobody publishes (unattributed);
- one late principal, served only once the connection has a baseline, that can disable users and
  does so once: the next collection raises `new-actor.v1` and `ungoverned-reach.v1` for it, and
  `process` raises `first-consequential-action.v1`.

Users, sponsors and owners are synthetic object ids. No name of a person, principal name,
address of anyone's, token or secret exists in it.
"""

import json
import re
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import parse_qsl, urlsplit
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

import httpx
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from execbound.audit import acted_with, append_event
from execbound.db import Database
from execbound.monitoring import graph
from execbound.monitoring.models import MonitorError
from execbound.monitoring.store import DEPENDENCY_ERRORS, SYSTEM_CLOCK, _session
from execbound.resolution.models import Clock
from execbound.spaces import SpaceError, narrowed, visible_spaces, write_space
from execbound.surfaces.sessions import Session

KIND = "fixture"
MODE = "synthetic"
LABEL = "Synthetic directory"
# 0099's fixed shape, which its checks hold every synthetic connection to.
BASE_URL = "https://synthetic-directory.invalid"
DIRECTORY = "5c007000-0000-4000-8000-000000000001"
CLIENT = "5c007000-0000-4000-8000-000000000002"
# Constants of a directory that exists only in this process: they authenticate nothing anywhere.
SECRET = "synthetic-directory-client"  # nosec B105 - authenticates nothing, never leaves the process
TOKEN = "synthetic-directory-token"  # nosec B105 - authenticates nothing, never leaves the process
# The application id Microsoft Graph has in every directory; the synthetic directory's own
# resource principal for it publishes the two app roles below.
MICROSOFT_GRAPH = "00000003-0000-0000-c000-000000000000"
# Anthropic's Claude for Microsoft 365 application, as the AI publisher catalog names it.
ANTHROPIC_APP = "08ad6f98-a4f8-4635-bb8d-f1a3044760f0"
# One address in Anthropic's published outbound range (`egress.PRODUCTION`), and one in a
# documentation block (RFC 5737), which no platform's egress can ever be.
ANTHROPIC_ADDRESS = "160.79.104.17"
NOBODY_ADDRESS = "192.0.2.10"
NAMESPACE = uuid5(NAMESPACE_URL, BASE_URL)


def _ref(number: int) -> str:
    return f"5c007000-0000-4000-8000-{number:012x}"


AGENT = _ref(0x101)
CONSENTED = _ref(0x102)
OFFBOARDING = _ref(0x103)
MANAGED = _ref(0x104)
REPORTING = _ref(0x105)
LATE = _ref(0x106)
BLUEPRINT_APP = _ref(0x201)
BLUEPRINT_OBJECT = _ref(0x202)
GRAPH_RESOURCE = _ref(0x501)
DISABLE_ROLE = _ref(0x601)
REVOKE_ROLE = _ref(0x602)
VENDOR = _ref(0x401)
# Every actor, in the order the collector lists them.
ACTORS = (AGENT, CONSENTED, OFFBOARDING, MANAGED, REPORTING, LATE)
CREATED = "2026-09-01T09:00:00Z"
# How many days back the daily entries go: inside every look-back the collector makes.
DAYS = 7

_FILTER_MOMENT = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?)Z")


def _moment(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _principal(
    ref: str, name: str, app: str, *, kind: str = "Application", owner: str | None = DIRECTORY
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "id": ref,
        "displayName": name,
        "accountEnabled": True,
        "createdDateTime": CREATED,
        "servicePrincipalType": kind,
        "appId": app,
        "tags": [],
    }
    if owner is not None:
        record["appOwnerOrganizationId"] = owner
    return record


def _days(now: datetime, hour: int) -> list[datetime]:
    """The last `DAYS` days' moments at `hour` o'clock UTC that are not after `now`."""
    today = now.astimezone(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
    moments = [today - timedelta(days=back) + timedelta(hours=hour) for back in range(DAYS + 1)]
    return sorted(moment for moment in moments if moment <= now)


def _audit(moment: datetime, actor: str, target: str, key: str) -> dict[str, Any]:
    return {
        "id": f"Directory_synthetic_{key}",
        "category": "UserManagement",
        "correlationId": str(uuid5(NAMESPACE, f"audit:{key}")),
        "result": "success",
        "activityDisplayName": "Disable account",
        "activityDateTime": _moment(moment),
        "loggedByService": "Core Directory",
        "operationType": "Update",
        "initiatedBy": {"app": {"servicePrincipalId": actor}, "user": None},
        "targetResources": [{"id": target, "type": "User", "modifiedProperties": []}],
    }


def _sign_in(moment: datetime, actor: str, address: str, agent: str, key: str) -> dict[str, Any]:
    return {
        "id": str(uuid5(NAMESPACE, f"sign-in:{key}")),
        "createdDateTime": _moment(moment),
        "servicePrincipalId": actor,
        "ipAddress": address,
        "userAgent": agent,
        "status": {"errorCode": 0},
        "signInEventTypes": ["servicePrincipal"],
    }


class Dataset:
    """What the synthetic directory holds at `now`, given the connection's `baseline`."""

    def __init__(self, now: datetime, baseline: datetime | None) -> None:
        self.now = now
        self.baseline = baseline
        self.agents = [
            {
                "id": AGENT,
                "displayName": "Synthetic support agent",
                "accountEnabled": True,
                "createdDateTime": CREATED,
                "agentIdentityBlueprintId": BLUEPRINT_APP,
                "servicePrincipalType": "ServiceIdentity",
                "tags": [],
            }
        ]
        principals = [
            _principal(
                CONSENTED, "Claude for Microsoft 365 (synthetic)", ANTHROPIC_APP, owner=VENDOR
            ),
            _principal(OFFBOARDING, "Synthetic offboarding automation", _ref(0x203)),
            _principal(
                MANAGED,
                "Synthetic function app identity",
                _ref(0x204),
                kind="ManagedIdentity",
                owner=None,
            ),
            _principal(REPORTING, "Synthetic reporting script", _ref(0x205)),
        ]
        # The late principal arrives once there is a baseline to be new against.
        self.late = baseline is not None
        if baseline is not None:
            late = _principal(LATE, "Synthetic triage bot", _ref(0x206))
            late["createdDateTime"] = _moment(baseline + timedelta(seconds=1))
            principals.append(late)
        self.principals = principals
        self.assignments: dict[str, list[dict[str, Any]]] = {
            OFFBOARDING: [{"appRoleId": DISABLE_ROLE, "resourceId": GRAPH_RESOURCE}],
            REPORTING: [{"appRoleId": REVOKE_ROLE, "resourceId": GRAPH_RESOURCE}],
            LATE: [{"appRoleId": DISABLE_ROLE, "resourceId": GRAPH_RESOURCE}],
        }
        self.delegated: dict[str, list[dict[str, Any]]] = {
            CONSENTED: [{"resourceId": GRAPH_RESOURCE, "scope": "User.Read Files.Read"}]
        }
        self.owners: dict[str, list[dict[str, Any]]] = {
            OFFBOARDING: [{"@odata.type": "#microsoft.graph.user", "id": _ref(0x302)}],
            LATE: [{"@odata.type": "#microsoft.graph.user", "id": _ref(0x303)}],
        }
        self.sponsors = {AGENT: [{"@odata.type": "#microsoft.graph.user", "id": _ref(0x301)}]}
        audits = [
            _audit(
                moment, OFFBOARDING, _ref(0x700 + moment.toordinal() % 0x100), f"{moment:%Y%m%d}"
            )
            for moment in _days(now, 9)
        ]
        if baseline is not None and baseline + timedelta(seconds=2) <= now:
            audits.append(
                _audit(
                    baseline + timedelta(seconds=2),
                    LATE,
                    _ref(0x800),
                    f"late-{baseline:%Y%m%d%H%M%S}",
                )
            )
        self.audits = sorted(audits, key=lambda entry: entry["activityDateTime"])
        self.sign_ins = sorted(
            [
                *(
                    _sign_in(
                        moment,
                        OFFBOARDING,
                        ANTHROPIC_ADDRESS,
                        "python-requests/2.32.3",
                        f"o{moment:%Y%m%d}",
                    )
                    for moment in _days(now, 8)
                ),
                *(
                    _sign_in(
                        moment, REPORTING, NOBODY_ADDRESS, "PowerShell/7.4.1", f"r{moment:%Y%m%d}"
                    )
                    for moment in _days(now, 8)
                ),
            ],
            key=lambda entry: entry["createdDateTime"],
            reverse=True,
        )

    def get(self, path: str, query: dict[str, str]) -> tuple[int, Any]:
        """One read's status and body, as Graph would answer it."""
        listed: dict[str, list[dict[str, Any]]] = {
            graph.AGENTS_PATH: self.agents,
            graph.PRINCIPALS_PATH: self.principals,
            graph.APPLICATIONS_PATH: [],
            graph.GRANTS_PATH: [],
            graph.ROLES_PATH: [],
            graph.BLUEPRINTS_PATH: [
                {
                    "id": BLUEPRINT_OBJECT,
                    "appId": BLUEPRINT_APP,
                    "keyCredentials": [{"type": "AsymmetricX509Cert"}],
                }
            ],
            "/v1.0/organization": [{"id": DIRECTORY}],
        }
        if path in listed:
            return 200, {"value": listed[path]}
        if path == graph.AUDIT_PATH:
            return 200, {"value": self._audits(query)}
        if path == graph.SIGN_INS_PATH:
            return 200, {"value": self._sign_ins(query)}
        if path == f"{graph.PRINCIPALS_PATH}/{GRAPH_RESOURCE}":
            return 200, {
                "appId": MICROSOFT_GRAPH,
                "appRoles": [
                    {"id": DISABLE_ROLE, "value": "User.EnableDisableAccount.All"},
                    {"id": REVOKE_ROLE, "value": "User.RevokeSessions.All"},
                ],
            }
        if path == f"{graph.BLUEPRINTS_PATH}/{BLUEPRINT_OBJECT}/inheritablePermissions":
            return 200, {"value": []}
        prefix = graph.PRINCIPALS_PATH + "/"
        if path.startswith(prefix):
            ref, _, rest = path[len(prefix) :].partition("/")
            held = {record["id"] for record in [*self.agents, *self.principals]}
            if ref in held:
                tables = {
                    "appRoleAssignments": self.assignments,
                    "oauth2PermissionGrants": self.delegated,
                    "memberOf": {},
                    "owners": self.owners if ref != AGENT else {},
                    "microsoft.graph.agentIdentity/sponsors": self.sponsors,
                    "microsoft.graph.agentIdentity/owners": {},
                }
                if rest in tables:
                    return 200, {"value": tables[rest].get(ref, [])}
        return 404, {"error": {"code": "Request_ResourceNotFound"}}

    def _start(self, query: dict[str, str]) -> datetime | None:
        found = _FILTER_MOMENT.search(query.get("$filter", ""))
        return None if found is None else datetime.fromisoformat(found[1]).replace(tzinfo=UTC)

    def _audits(self, query: dict[str, str]) -> list[dict[str, Any]]:
        start = self._start(query)
        top = int(query.get("$top", "100"))
        if start is None:
            # The capability probe asks for one entry, newest first.
            return list(reversed(self.audits))[:top]
        return [entry for entry in self.audits if entry["activityDateTime"] >= _moment(start)][:top]

    def _sign_ins(self, query: dict[str, str]) -> list[dict[str, Any]]:
        start = self._start(query)
        top = int(query.get("$top", "1000"))
        floor = _moment(start) if start is not None else ""
        return [entry for entry in self.sign_ins if entry["createdDateTime"] >= floor][:top]


def _respond(status: int, body: Any) -> httpx.Response:
    return httpx.Response(
        status, content=json.dumps(body).encode(), headers={"Content-Type": "application/json"}
    )


def handler(now: datetime, baseline: datetime | None) -> Any:
    """The in-process directory's answers to every request a collection makes at `now`."""
    data = Dataset(now, baseline)
    graph_host = urlsplit(graph.GRAPH_ORIGIN).hostname
    login_host = urlsplit(graph.LOGIN_ORIGIN).hostname

    def answer(request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and request.url.host == login_host:
            form = dict(parse_qsl(request.content.decode("ascii", "replace")))
            if (
                request.url.path != f"/{DIRECTORY}/oauth2/v2.0/token"
                or form.get("client_id") != CLIENT
                or form.get("client_secret") != SECRET
            ):
                return _respond(401, {"error": "invalid_client"})
            # The scheme name of a token response, and the in-process constant: no secret.
            answer = {"token_type": "Bearer", "expires_in": 3599, "access_token": TOKEN}  # nosec B105 - a scheme name
            return _respond(200, answer)
        if request.method != "GET" or request.url.host != graph_host:
            return _respond(404, {"error": {"code": "Request_ResourceNotFound"}})
        if request.headers.get("Authorization") != f"Bearer {TOKEN}":
            return _respond(401, {"error": {"code": "InvalidAuthenticationToken"}})
        query = dict(parse_qsl(request.url.query.decode("ascii", "replace")))
        status, body = data.get(request.url.path, query)
        return _respond(status, body)

    return answer


def client(now: datetime, baseline: datetime | None) -> httpx.Client:
    """The one client a synthetic connection is read with: in process, with no network."""
    return httpx.Client(
        transport=httpx.MockTransport(handler(now, baseline)), follow_redirects=False
    )


# The definer function's refusals, each to the code a caller sees.
_REFUSALS = {
    "INVALID_TENANT": "INVALID_ADMIN",
    "INVALID_ACTOR": "INVALID_ADMIN",
    "INVALID_SPACE": "SPACE_REQUIRED",
    "SPACE_ARCHIVED": "SPACE_ARCHIVED",
    "CONNECTION_CAPACITY": "CONNECTION_CAPACITY",
    "CONNECTION_EXISTS": "CONNECTION_EXISTS",
    "DIRECTORY_CONNECTED": "DIRECTORY_CONNECTED",
    "INVALID_INPUT": "INVALID_INPUT",
}


def add(db: Database, session: Session, *, clock: Clock = SYSTEM_CLOCK) -> UUID:
    """Add the workspace's synthetic directory in the session's Space, as a workspace
    administrator.

    `admin_add_synthetic_directory` is the one writer: an active workspace administrator, one no
    membership narrows to their Spaces, because the directory is the whole workspace's (while it
    is present no Space connects Microsoft Entra, and adding it asks whether any Space ever did);
    an administrator of the Space it lands in; a workspace under its connection capacity, holding
    no Microsoft Entra connection, active or revoked, and no other active synthetic directory. It
    asks for the first collection at once, and the change appends `monitor.connection_created`
    with kind `fixture` and mode `synthetic` as its last write. A narrowed administrator is
    refused here before the function is asked, and by the function again.
    """
    identity = session.identity
    connection_id = uuid4()
    try:
        with db.transaction(identity.tenant_id) as conn:
            _session(conn, session, clock)
            if narrowed(conn, identity.tenant_id, identity.principal_id):
                raise MonitorError("INVALID_ADMIN")
            try:
                space = write_space(conn, identity.tenant_id, visible_spaces(conn, session))
            except SpaceError:
                raise MonitorError("SPACE_REQUIRED") from None
            conn.execute(
                text("SELECT execbound.admin_add_synthetic_directory(:a, :s, :c)"),
                {"a": identity.principal_id, "s": space, "c": connection_id},
            )
            _session(conn, session, clock)
            append_event(
                conn,
                identity.tenant_id,
                identity.principal_id,
                "monitor.connection_created",
                {
                    "connection_id": str(connection_id),
                    "space_id": str(space),
                    "kind": KIND,
                    "credential_mode": MODE,
                    "label": LABEL,
                    **acted_with(identity.credential_id),
                },
                space=space,
            )
    except DBAPIError as exc:
        diagnostic = getattr(exc.orig, "diag", None)
        message = str(getattr(diagnostic, "message_primary", None) or "")
        raise MonitorError(_REFUSALS.get(message, "MONITOR_UNAVAILABLE")) from None
    except DEPENDENCY_ERRORS:
        raise MonitorError() from None
    return connection_id
