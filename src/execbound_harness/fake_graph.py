# SPDX-License-Identifier: AGPL-3.0-only
"""A local fake of Microsoft Graph and its login endpoint for Scout collector tests.

Serves recorded response *shapes* over loopback so the collector's real URL building,
headers, paging, status handling and response bounds run against a socket. It never contacts
a vendor and holds only synthetic records. Tests reach it through :func:`transport`, which
rewrites both pinned origins onto the loopback port, so the collector keeps its real origin
pins instead of being handed a test URL.
"""

import base64
import hashlib
import json
import re
import threading
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)
from cryptography.x509.oid import NameOID

from execbound.monitoring.graph import (
    AGENTS_PATH,
    APPLICATIONS_PATH,
    AUDIT_PATH,
    DELTA_PATH,
    GRAPH_ORIGIN,
    LOGIN_ORIGIN,
    PRINCIPALS_PATH,
    SIGN_INS_PATH,
)

DIRECTORY = "11111111-2222-3333-4444-555555555555"
CLIENT = "66666666-7777-8888-9999-aaaaaaaaaaaa"
# Synthetic values for a fake directory on loopback; neither authenticates anything.
SECRET = "synthetic-client-secret"  # nosec B105 - synthetic, authenticates nothing
TOKEN = "synthetic.access.token"  # nosec B105 - synthetic, authenticates nothing
MICROSOFT_GRAPH = "00000003-0000-0000-c000-000000000000"
GRANTS_PATH = "/v1.0/oauth2PermissionGrants"
ROLES_PATH = "/v1.0/directoryRoles"
ORGANIZATION_PATH = "/v1.0/organization"
BLUEPRINTS_PATH = "/v1.0/applications/microsoft.graph.agentIdentityBlueprint"
AGENT_CAST = "/microsoft.graph.agentIdentity"
# RFC 7523's client assertion type, as Microsoft's token endpoint takes a certificate credential.
ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
# The clock skew the fake allows an assertion's times.
SKEW = 60
# The one filter the audit read may send: Core Directory entries from a moment, to the second or
# to the microsecond (#355).
AUDIT_FILTER = re.compile(
    r"activityDateTime ge (\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{6})?Z) "
    r"and loggedByService eq 'Core Directory'"
)
# The one filter a service principal sign-in read or its probe may send (#355).
SIGN_IN_FILTER = re.compile(
    r"createdDateTime ge (\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z) "
    r"and signInEventTypes/any\(t: t eq 'servicePrincipal'\)"
)


def platform_app(client_id: str = CLIENT) -> dict[str, str]:
    """A synthetic platform app credential, as the collector's `scout-app.json` holds one: a
    fresh RSA key, a self-signed certificate for it, and the app's client id. It is registered
    with a fake directory by giving the certificate to `Scenario.certificate`."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic platform app")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=90))
        .sign(key, hashes.SHA256())
    )
    return {
        "client_id": client_id,
        "certificate_pem": certificate.public_bytes(Encoding.PEM).decode("ascii"),
        "private_key_pem": key.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        ).decode("ascii"),
    }


def _segment(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def assertion_claims(token: str, certificate_pem: str, audience: str) -> dict[str, Any] | None:
    """An RFC 7523 client assertion's claims, if a token endpoint would take it: RS256 signed
    by the registered certificate's key, naming that certificate by its SHA-256 thumbprint, for
    this endpoint, and current. None otherwise, as Microsoft answers `invalid_client`."""
    certificate = x509.load_pem_x509_certificate(certificate_pem.encode("ascii"))
    try:
        encoded_header, encoded_payload, encoded_signature = token.split(".")
        header = json.loads(_segment(encoded_header))
        payload = json.loads(_segment(encoded_payload))
        signature = _segment(encoded_signature)
    except ValueError:
        return None
    thumbprint = (
        base64.urlsafe_b64encode(hashlib.sha256(certificate.public_bytes(Encoding.DER)).digest())
        .decode("ascii")
        .rstrip("=")
    )
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    if header.get("alg") != "RS256" or header.get("x5t#S256") != thumbprint:
        return None
    public = certificate.public_key()
    if not isinstance(public, rsa.RSAPublicKey):
        return None
    try:
        public.verify(
            signature,
            f"{encoded_header}.{encoded_payload}".encode("ascii"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except InvalidSignature:
        return None
    now = time.time()
    expiry, valid_from = payload.get("exp"), payload.get("nbf")
    if (
        payload.get("aud") != audience
        or type(expiry) is not int
        or type(valid_from) is not int
        or not valid_from - SKEW <= now < expiry + SKEW
        or type(payload.get("jti")) is not str
        or not payload["jti"]
    ):
        return None
    return payload


@dataclass
class Scenario:
    """Records and failure modes one synthetic directory serves."""

    agents: list[dict[str, Any]] = field(default_factory=list)
    principals: list[dict[str, Any]] = field(default_factory=list)
    applications: list[dict[str, Any]] = field(default_factory=list)
    blueprints: list[dict[str, Any]] = field(default_factory=list)
    # Keyed by the principal's object identifier.
    app_role_assignments: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    delegated_grants: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    member_of: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    sponsors: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    owners: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    # Keyed by the blueprint application's object identifier.
    inheritable: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    # The resource service principals an assignment points at, by object identifier.
    resources: dict[str, dict[str, Any]] = field(default_factory=dict)
    # The directory identifier the tenant reports for itself; the connection's own
    # directory reference must agree with it or the run is quarantined.
    organization: str | None = DIRECTORY
    max_top: int = 100
    # A collection key ("agents", "principals", ...) to a forced status code.
    status: dict[str, int] = field(default_factory=dict)
    token_status: int = 200
    retry_after: str | None = None
    # Bytes of filler added to every agent record, to exercise the response size bound.
    padding: int = 0
    # An absolute continuation the fake returns instead of its own, to prove the collector
    # refuses a next link that leaves the pinned origin or changes the read.
    next_link: str | None = None
    # Users the disable path reads and writes, keyed by object identifier. Separate from the
    # collector's records because the connector and the collector hold separate
    # registrations and read different things.
    users: dict[str, dict[str, Any]] = field(default_factory=dict)
    # Applied to the user after its read and before the write it is compared for: the race a
    # vendor with no conditional write cannot refuse on the connector's behalf.
    race: dict[str, Any] | None = None
    # A forced status for the write, to exercise a refusal that is not a race.
    write_status: int = 204
    # The platform app's registered certificate (PEM), which a client assertion must be signed
    # for, and the app's client id, which it must name as issuer and subject.
    certificate: str | None = None
    app_client: str = CLIENT
    # `servicePrincipals/delta`. The entries the next round that starts from a delta token
    # returns, as Graph writes them: a principal's standard representation, only its changed
    # properties, or its `id` with `@removed`. A round that reaches its delta link consumes them.
    delta: list[dict[str, Any]] = field(default_factory=list)
    # Whether `$deltatoken=latest` is served; when not, it is refused with a 400, as a service
    # that does not offer "sync from now" would, and the collector walks an initial round.
    delta_latest: bool = True
    # How many entries one delta page carries; delta takes no `$top`.
    delta_page: int = 100
    # A delta link or a next link the fake returns instead of its own, to prove the collector
    # refuses one that leaves the pinned origin or the delta path.
    delta_link: str | None = None
    delta_next_link: str | None = None
    # A page of a round from a delta token that Graph's protocol never sends, from the page at
    # `delta_malformed_at` on: "body" is not JSON, "value" is not a list, and "both" and
    # "neither" carry both continuation links or neither. The round is not consumed.
    delta_malformed: str | None = None
    delta_malformed_at: int = 0
    # `auditLogs/directoryAudits` (#355): the entries the directory's audit log holds, as Graph
    # writes them. A read must ask for Core Directory entries from a moment, oldest first, and is
    # served what matches in that order, in pages of `$top` (bounded by `max_top`); a request with
    # no filter, as the capability probe sends, is served newest first. `status["audits"]`
    # forces a status for every audit request, the probe included.
    audits: list[dict[str, Any]] = field(default_factory=list)
    # A forced status for a read that names a filter, leaving the probe as it is.
    audit_status: int | None = None
    # A forced status for a page a next link asks for, as a read throttled part way through.
    audit_page_status: int | None = None
    # A next link the fake returns instead of its own, to prove the collector refuses one that
    # leaves the pinned origin or the audit path.
    audit_next_link: str | None = None
    # Whether a read is served newest first whatever it asked, as a service that ignored
    # `$orderby` would.
    audit_descending: bool = False
    # Beta `auditLogs/signIns` (#355): the sign-ins the directory's log holds, as Graph writes
    # them, every field included whatever `$select` asked. A request must name the service
    # principal filter from a moment, or it is refused with a 400, and is served what matches,
    # newest first, in pages of `$top` (bounded by `sign_in_max_top`). `sign_in_status` forces a
    # status for every sign-in request, the probe included, as a directory without P1 or P2, or a
    # registration refused the log, answers 403; `sign_in_page_status` one for a page a next
    # link asks for; `sign_in_next_link` replaces the fake's own next link.
    sign_ins: list[dict[str, Any]] = field(default_factory=list)
    sign_in_status: int | None = None
    sign_in_page_status: int | None = None
    sign_in_next_link: str | None = None
    sign_in_max_top: int = 1000


class _Handler(BaseHTTPRequestHandler):
    server: "FakeGraph"
    protocol_version = "HTTP/1.1"

    def log_message(self, *args: Any) -> None:  # pragma: no cover - keep test output clean
        return

    def do_POST(self) -> None:
        url = urlsplit(self.path)
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(min(length, 65536)).decode("utf-8", "replace")
        self.server.requests.append((url.path, {}, dict(self.headers)))
        scenario = self.server.scenario
        if not url.path.endswith("/oauth2/v2.0/token"):
            self._send(404, {"error": "not found"})
            return
        if scenario.token_status != 200:
            headers = {}
            if scenario.token_status == 429 and scenario.retry_after is not None:
                headers["Retry-After"] = scenario.retry_after
            self._send(scenario.token_status, {"error": "invalid_client"}, headers)
            return
        form = {key: values[-1] for key, values in parse_qs(body).items()}
        if "client_assertion" in form:
            claims = (
                None
                if scenario.certificate is None
                or form.get("client_assertion_type") != ASSERTION_TYPE
                or form.get("client_id") != scenario.app_client
                else assertion_claims(
                    form["client_assertion"], scenario.certificate, LOGIN_ORIGIN + url.path
                )
            )
            if claims is None or not claims.get("iss") == claims.get("sub") == scenario.app_client:
                self._send(401, {"error": "invalid_client"})
                return
            self.server.assertions.append(claims)
        elif f"client_secret={SECRET}" not in body.replace("+", " ").replace("%20", " "):
            self._send(401, {"error": "invalid_client"})
            return
        # The scheme name in a synthetic token response, not a secret.
        self._send(
            200,
            {"token_type": "Bearer", "expires_in": 3599, "access_token": TOKEN},  # nosec B105 - a scheme
        )

    def do_GET(self) -> None:
        url = urlsplit(self.path)
        query = {key: values[-1] for key, values in parse_qs(url.query).items()}
        self.server.requests.append((url.path, dict(query), dict(self.headers)))
        scenario = self.server.scenario
        if self.headers.get("Authorization") != f"Bearer {TOKEN}":
            self._send(401, {"error": {"code": "InvalidAuthenticationToken"}})
            return
        if url.path.startswith("/v1.0/users/"):
            self._send_user(url.path.rsplit("/", 1)[-1])
            return
        if url.path == DELTA_PATH:
            self._send_delta(query)
            return
        if url.path == AUDIT_PATH:
            self._send_audits(query)
            return
        if url.path == SIGN_INS_PATH:
            self._send_sign_ins(query)
            return
        key, records = self.server.records(url.path)
        if key is None:
            self._send(404, {"error": {"code": "ResourceNotFound"}})
            return
        if key == "resource":
            self._send(200, records)
            return
        forced = scenario.status.get(key)
        if forced is not None:
            headers = {}
            if forced == 429 and scenario.retry_after is not None:
                headers["Retry-After"] = scenario.retry_after
            self._send(forced, {"error": {"code": "Forced"}}, headers)
            return
        try:
            top = min(int(query.get("$top", "100")), scenario.max_top)
            skip = int(query.get("$skiptoken", "0"))
        except ValueError:
            self._send(400, {"error": {"code": "BadRequest"}})
            return
        if top < 1 or skip < 0:
            self._send(400, {"error": {"code": "BadRequest"}})
            return
        window = list(records[skip : skip + top])
        if scenario.padding and key == "agents":
            window = [{**record, "notes": "x" * scenario.padding} for record in window]
        body: dict[str, Any] = {"value": window}
        if skip + top < len(records):
            body["@odata.nextLink"] = scenario.next_link or (
                f"{GRAPH_ORIGIN}{url.path}?$top={top}&$skiptoken={skip + top}"
            )
        self._send(200, body)

    def _send_delta(self, query: dict[str, str]) -> None:
        """One page of `servicePrincipals/delta`, as Graph pages a round.

        `$deltatoken=latest` answers an empty page and a delta link. No token starts an initial
        round over the directory as it stands. A token the fake issued starts a round over
        `Scenario.delta`; any other token is a 410, as an expired one is. A page carries a next
        link or a delta link, never both; the skip token names the round and its offset.
        """
        scenario = self.server.scenario
        token, skip = query.get("$deltatoken"), query.get("$skiptoken")
        if skip is not None:
            mode, _, offset_text = skip.partition(".")
            try:
                offset = int(offset_text)
            except ValueError:
                self._send(400, {"error": {"code": "BadRequest"}})
                return
            if mode not in {"initial", "changes"} or offset < 0:
                self._send(400, {"error": {"code": "BadRequest"}})
                return
        elif token == "latest":  # nosec B105 - Graph's "sync from now" keyword, not a secret
            if not scenario.delta_latest:
                self._send(400, {"error": {"code": "Request_UnsupportedQuery"}})
                return
            link = scenario.delta_link or self.server.issue()
            self._send(200, {"value": [], "@odata.deltaLink": link})
            return
        elif token is not None:
            if token not in self.server.issued:
                self._send(410, {"error": {"code": "syncStateNotFound"}})
                return
            mode, offset = "changes", 0
        else:
            mode, offset = "initial", 0
        forced = scenario.status.get("delta")
        if mode == "changes" and forced is not None:
            headers = {}
            if forced == 429 and scenario.retry_after is not None:
                headers["Retry-After"] = scenario.retry_after
            self._send(forced, {"error": {"code": "Forced"}}, headers)
            return
        entries = (
            scenario.delta
            if mode == "changes"
            else [
                *(
                    {**record, "servicePrincipalType": "ServiceIdentity"}
                    for record in scenario.agents
                ),
                *scenario.principals,
            ]
        )
        window = list(entries[offset : offset + scenario.delta_page])
        malformed = (
            scenario.delta_malformed
            if mode == "changes" and offset >= scenario.delta_malformed_at
            else None
        )
        if malformed == "body":
            self._send_raw(200, b"<html>not a Graph page</html>")
            return
        body: dict[str, Any] = {"value": {"entries": window} if malformed == "value" else window}
        following = f"{GRAPH_ORIGIN}{DELTA_PATH}?$skiptoken={mode}.{offset + scenario.delta_page}"
        if malformed == "both":
            body["@odata.nextLink"] = following
            body["@odata.deltaLink"] = self.server.issue()
        elif malformed == "neither":
            pass
        elif offset + scenario.delta_page < len(entries):
            body["@odata.nextLink"] = scenario.delta_next_link or following
        else:
            body["@odata.deltaLink"] = scenario.delta_link or self.server.issue()
            if mode == "changes" and malformed is None:
                scenario.delta = []
        self._send(200, body)

    def _send_audits(self, query: dict[str, str]) -> None:
        """One page of `auditLogs/directoryAudits`, as Graph pages it.

        A read names the filter `AUDIT_FILTER` describes and `$orderby=activityDateTime asc`,
        or it is refused with a 400, as a query the fake does not serve. Its next link spells
        the path in lower case, as Graph's own links may, and carries the read's query with an
        offset as its skip token.
        """
        scenario = self.server.scenario
        forced = scenario.status.get("audits")
        filtered = query.get("$filter")
        if forced is None and filtered is not None:
            forced = scenario.audit_status
        if forced is None and "$skiptoken" in query:
            forced = scenario.audit_page_status
        if forced is not None:
            headers = {}
            if forced == 429 and scenario.retry_after is not None:
                headers["Retry-After"] = scenario.retry_after
            self._send(forced, {"error": {"code": "Forced"}}, headers)
            return

        def moment(entry: dict[str, Any]) -> datetime:
            return datetime.fromisoformat(str(entry["activityDateTime"]).replace("Z", "+00:00"))

        if filtered is None:
            entries = sorted(scenario.audits, key=moment, reverse=True)
        else:
            matched = AUDIT_FILTER.fullmatch(filtered)
            if matched is None or query.get("$orderby") != "activityDateTime asc":
                self._send(400, {"error": {"code": "Request_UnsupportedQuery"}})
                return
            start = datetime.fromisoformat(matched[1].replace("Z", "+00:00"))
            entries = sorted(
                (
                    entry
                    for entry in scenario.audits
                    if entry.get("loggedByService") == "Core Directory" and moment(entry) >= start
                ),
                key=moment,
                reverse=scenario.audit_descending,
            )
        try:
            top = min(int(query.get("$top", "100")), scenario.max_top)
            skip = int(query.get("$skiptoken", "0"))
        except ValueError:
            self._send(400, {"error": {"code": "BadRequest"}})
            return
        if top < 1 or skip < 0:
            self._send(400, {"error": {"code": "BadRequest"}})
            return
        body: dict[str, Any] = {
            "@odata.context": f"{GRAPH_ORIGIN}/v1.0/$metadata#auditLogs/directoryAudits",
            "value": entries[skip : skip + top],
        }
        if skip + top < len(entries):
            following = {
                key: value for key, value in query.items() if key in {"$filter", "$orderby"}
            }
            body["@odata.nextLink"] = scenario.audit_next_link or (
                f"{GRAPH_ORIGIN}{AUDIT_PATH.lower()}?"
                + urlencode({**following, "$top": top, "$skiptoken": skip + top})
            )
        self._send(200, body)

    def _send_sign_ins(self, query: dict[str, str]) -> None:
        """One page of beta `auditLogs/signIns` filtered to service principals, newest first, as
        Graph serves it. Its next link spells the path in lower case, as Graph's own example
        does, and carries the read's filter with an offset as its skip token."""
        scenario = self.server.scenario
        forced = scenario.sign_in_status
        if forced is None and "$skiptoken" in query:
            forced = scenario.sign_in_page_status
        if forced is not None:
            headers = {}
            if forced == 429 and scenario.retry_after is not None:
                headers["Retry-After"] = scenario.retry_after
            self._send(forced, {"error": {"code": "Forced"}}, headers)
            return
        matched = SIGN_IN_FILTER.fullmatch(query.get("$filter", ""))
        if matched is None:
            self._send(400, {"error": {"code": "Request_UnsupportedQuery"}})
            return
        start = datetime.fromisoformat(matched[1].replace("Z", "+00:00"))

        def moment(entry: dict[str, Any]) -> datetime:
            return datetime.fromisoformat(str(entry["createdDateTime"]).replace("Z", "+00:00"))

        entries = sorted(
            (
                entry
                for entry in scenario.sign_ins
                if "servicePrincipal" in entry.get("signInEventTypes", [])
                and moment(entry) >= start
            ),
            key=moment,
            reverse=True,
        )
        try:
            top = min(int(query.get("$top", "1000")), scenario.sign_in_max_top)
            skip = int(query.get("$skiptoken", "0"))
        except ValueError:
            self._send(400, {"error": {"code": "BadRequest"}})
            return
        if top < 1 or skip < 0:
            self._send(400, {"error": {"code": "BadRequest"}})
            return
        body: dict[str, Any] = {
            "@odata.context": f"{GRAPH_ORIGIN}/beta/$metadata#auditLogs/signIns",
            "value": entries[skip : skip + top],
        }
        if skip + top < len(entries):
            following = {key: value for key, value in query.items() if key in {"$filter"}}
            body["@odata.nextLink"] = scenario.sign_in_next_link or (
                f"{GRAPH_ORIGIN}{SIGN_INS_PATH.lower()}?"
                + urlencode({**following, "$top": top, "$skiptoken": skip + top})
            )
        self._send(200, body)

    def _send_user(self, user_id: str) -> None:
        scenario = self.server.scenario
        user = scenario.users.get(user_id)
        if user is None:
            self._send(404, {"error": {"code": "ResourceNotFound"}})
            return
        # Graph echoes the context of a $select; the connector must drop it rather than
        # treat it as a field the recipe does not know.
        self._send(200, {"@odata.context": f"{GRAPH_ORIGIN}/v1.0/$metadata#users", **user})
        # The race is applied after the read the connector will compare, which is the whole
        # point: a vendor with no conditional write cannot refuse it on the caller's behalf.
        if scenario.race is not None:
            user.update(scenario.race)
            scenario.race = None

    def do_PATCH(self) -> None:
        url = urlsplit(self.path)
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(min(length, 65536))
        self.server.requests.append((url.path, {}, dict(self.headers)))
        scenario = self.server.scenario
        if self.headers.get("Authorization") != f"Bearer {TOKEN}":
            self._send(401, {"error": {"code": "InvalidAuthenticationToken"}})
            return
        if not url.path.startswith("/v1.0/users/"):
            self._send(404, {"error": {"code": "ResourceNotFound"}})
            return
        user = scenario.users.get(url.path.rsplit("/", 1)[-1])
        if user is None:
            self._send(404, {"error": {"code": "ResourceNotFound"}})
            return
        if scenario.write_status not in {200, 204}:
            self._send(scenario.write_status, {"error": {"code": "Forced"}})
            return
        try:
            change = json.loads(raw)
        except ValueError:
            self._send(400, {"error": {"code": "BadRequest"}})
            return
        user.update(change if isinstance(change, dict) else {})
        if scenario.write_status == 204:
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self._send(200, dict(user))

    def _send(self, status: int, body: object, headers: Mapping[str, str] = {}) -> None:
        self._send_raw(status, json.dumps(body).encode(), headers)

    def _send_raw(self, status: int, raw: bytes, headers: Mapping[str, str] = {}) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        for name, value in headers.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(raw)


class FakeGraph(ThreadingHTTPServer):
    """One synthetic directory on loopback, serving Graph and its login endpoint."""

    daemon_threads = True

    def __init__(self, scenario: Scenario) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.scenario = scenario
        self.requests: list[tuple[str, dict[str, str], dict[str, str]]] = []
        # The claims of every client assertion the token endpoint took.
        self.assertions: list[dict[str, Any]] = []
        # The delta tokens this directory issued, each valid until the test says otherwise.
        self.issued: set[str] = set()

    def issue(self) -> str:
        """A fresh delta token, as a delta link on the pinned origin and path."""
        token = f"token{len(self.issued) + 1}"
        self.issued.add(token)
        return f"{GRAPH_ORIGIN}{DELTA_PATH}?$deltatoken={token}"

    @property
    def origin(self) -> str:
        return f"http://127.0.0.1:{self.server_address[1]}"

    def records(self, path: str) -> tuple[str | None, Any]:
        scenario = self.scenario
        simple = {
            AGENTS_PATH: ("agents", scenario.agents),
            PRINCIPALS_PATH: ("principals", scenario.principals),
            APPLICATIONS_PATH: ("applications", scenario.applications),
            BLUEPRINTS_PATH: ("blueprints", scenario.blueprints),
            GRANTS_PATH: ("grants", []),
            ROLES_PATH: ("directory_roles", []),
            ORGANIZATION_PATH: (
                "organization",
                [{"id": scenario.organization}] if scenario.organization else [],
            ),
        }
        if path in simple:
            return simple[path]
        for suffix, key, table in (
            ("/appRoleAssignments", "assignments", scenario.app_role_assignments),
            ("/oauth2PermissionGrants", "grants", scenario.delegated_grants),
            ("/memberOf", "member_of", scenario.member_of),
            (f"{AGENT_CAST}/sponsors", "sponsors", scenario.sponsors),
            (f"{AGENT_CAST}/owners", "owners", scenario.owners),
            ("/owners", "owners", scenario.owners),
        ):
            if path.startswith(f"{PRINCIPALS_PATH}/") and path.endswith(suffix):
                return key, table.get(path[len(PRINCIPALS_PATH) + 1 : -len(suffix)], [])
        if path.startswith(f"{BLUEPRINTS_PATH}/") and path.endswith("/inheritablePermissions"):
            blueprint = path[len(BLUEPRINTS_PATH) + 1 : -len("/inheritablePermissions")]
            return "inheritable", scenario.inheritable.get(blueprint, [])
        if path.startswith(f"{PRINCIPALS_PATH}/"):
            resource = scenario.resources.get(path[len(PRINCIPALS_PATH) + 1 :])
            if resource is not None:
                return "resource", resource
        if path.startswith(f"{APPLICATIONS_PATH}/"):
            wanted = path[len(APPLICATIONS_PATH) + 1 :]
            for application in scenario.applications:
                if application.get("id") == wanted:
                    return "resource", application
        return None, ()

    def paths(self) -> list[str]:
        return [path for path, _, _ in self.requests]


class _Rewriting(httpx.BaseTransport):
    """Send a request built for a pinned origin to the loopback fake instead."""

    def __init__(self, origin: str) -> None:
        self._origin = urlsplit(origin)
        self._pinned = {urlsplit(GRAPH_ORIGIN).hostname, urlsplit(LOGIN_ORIGIN).hostname}
        self._inner = httpx.HTTPTransport(trust_env=False, retries=0)

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        if request.url.host not in self._pinned:
            raise httpx.ConnectError("Unpinned origin")
        request.url = request.url.copy_with(
            scheme=self._origin.scheme, host=self._origin.hostname, port=self._origin.port
        )
        return self._inner.handle_request(request)

    def close(self) -> None:
        self._inner.close()


@contextmanager
def serving(scenario: Scenario) -> Iterator[FakeGraph]:
    server = FakeGraph(scenario)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def transport(server: FakeGraph) -> httpx.BaseTransport:
    return _Rewriting(server.origin)
