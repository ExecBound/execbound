# SPDX-License-Identifier: Apache-2.0
"""The read-compare-write a Graph user disable needs, and nothing that decides anything.

Microsoft Graph offers no conditional write for a user object, so a dispatch against it
cannot ask the vendor to enforce the frozen precondition. What this client does instead is
read the state, hash it with the one recipe in ``provider.composite``, compare it with the
composite the plan froze, and only then send a single write. That is a check ExecBound made
itself, with both vendor responses retained and the gap between them measured, which is
exactly what ``CHECKED_BY_CONNECTOR`` claims and no more.

The window is measured and returned, never enforced. Refusing a dispatch because the gap
was wide would invent a guarantee the vendor does not give; the number is evidence a reader
can weigh, not a gate.

This module holds no authority. It does not decide, settle, retry or interpret policy: it
performs one bounded exchange and hands back what it saw. How that becomes settlement
evidence, and under which tier a vendor that co-signs nothing can settle at all, is a
separate contract this deliberately does not assume.
"""

import json
import time
from dataclasses import dataclass, field

import httpx
from execbound_protocol.composite import GRAPH_USER_FIELDS, CompositeDrift, graph_user_composite

# The pinned origins have exactly one definition in the source, here; the monitoring
# collector names them from this module. Two would be two things to keep in step, and a
# drifted security pin is worse than an import across packages.
GRAPH_ORIGIN = "https://graph.microsoft.com"
LOGIN_ORIGIN = "https://login.microsoftonline.com"

GRAPH_SCOPE = "https://graph.microsoft.com/.default"
# One user object and one empty write response; anything larger is not the shape expected.
MAX_BODY = 64 * 1024
TIMEOUT = httpx.Timeout(10.0)
USER_SELECT = ",".join(GRAPH_USER_FIELDS)


class GraphDispatchError(Exception):
    """A bounded, reason-carrying failure. The reason never contains a vendor body.

    A refusal carries what the exchange had already seen when it refused, because for one
    of them the observation *is* the evidence: a VERSION_MISMATCH record is required to
    retain the composite that differed, and a record whose observed value equals the frozen
    one is refused at construction. Throwing the drift away here would leave the connector
    unable to state the one thing ``CHECKED_BY_CONNECTOR`` exists to prove. The fields are
    None on every reason that saw nothing to report.
    """

    def __init__(
        self,
        reason: str,
        *,
        observed: str | None = None,
        window_ms: int | None = None,
        status: int | None = None,
    ) -> None:
        super().__init__(reason)
        self.reason = reason
        self.observed = observed
        self.window_ms = window_ms
        self.status = status


@dataclass(frozen=True)
class GraphCredential:
    """One app registration that may disable a user, and nothing else.

    The Scout collector holds its own registration with read-only directory permissions;
    this one carries the write permission and no discovery permission. One client secret
    that both reads the directory and disables users is the concentration the monitoring
    design and the credential boundary forbid.
    """

    directory: str
    client_id: str
    secret: str = field(repr=False)

    def __post_init__(self) -> None:
        if not (self.directory and self.client_id and self.secret):
            raise ValueError("Invalid Graph credential")


@dataclass(frozen=True)
class GraphDisable:
    """What one disable exchange saw, for a caller that decides what it is worth."""

    observed: str
    """The composite the connector computed from its own read, immediately before writing."""
    window_ms: int
    """Milliseconds between the read that was compared and the write that followed it."""
    patched: bool
    status: int
    """The status the vendor returned for the write, retained rather than assumed.

    A record claiming EXECUTED must carry a 2xx, and the one that arrived is what it must
    carry: a connector that filled in 204 because it did not raise would be signing a
    number it never saw.
    """
    before: dict[str, object]


class GraphUserWriter:
    """One bounded read-compare-write against a pinned Graph origin."""

    def __init__(self, credential: GraphCredential, client: httpx.Client | None = None) -> None:
        self._credential = credential
        self._client = client or httpx.Client(
            # No retry, ever: a resend of a write whose response was lost cannot tell its own
            # earlier success from someone else re-enabling the account and the state moving.
            transport=httpx.HTTPTransport(retries=0, trust_env=False),
            trust_env=False,
            follow_redirects=False,
            timeout=TIMEOUT,
        )

    def close(self) -> None:
        self._client.close()

    def _token(self) -> str:
        """The one POST of a dispatch. The token is a local value and is never persisted."""
        try:
            response = self._client.post(
                f"{LOGIN_ORIGIN}/{self._credential.directory}/oauth2/v2.0/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": self._credential.client_id,
                    "client_secret": self._credential.secret,
                    "scope": GRAPH_SCOPE,
                },
                headers={"Accept": "application/json"},
                follow_redirects=False,
            )
        except httpx.HTTPError:
            raise GraphDispatchError("UNAVAILABLE") from None
        if response.status_code in {400, 401, 403}:
            raise GraphDispatchError("AUTH_LOST")
        if response.status_code != 200 or len(response.content) > MAX_BODY:
            raise GraphDispatchError("UNAVAILABLE")
        try:
            body = json.loads(response.content)
        except ValueError:
            raise GraphDispatchError("MALFORMED") from None
        token = body.get("access_token") if isinstance(body, dict) else None
        if type(token) is not str or not token:
            raise GraphDispatchError("MALFORMED")
        return token

    def _read_user(self, token: str, user_id: str) -> dict[str, object]:
        try:
            response = self._client.get(
                f"{GRAPH_ORIGIN}/v1.0/users/{user_id}",
                params={"$select": USER_SELECT},
                headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
                follow_redirects=False,
            )
        except httpx.HTTPError:
            raise GraphDispatchError("UNAVAILABLE") from None
        if response.status_code in {401, 403}:
            raise GraphDispatchError("FORBIDDEN")
        if response.status_code == 404:
            raise GraphDispatchError("TARGET_ABSENT", status=404)
        if response.status_code != 200 or len(response.content) > MAX_BODY:
            raise GraphDispatchError("UNAVAILABLE")
        try:
            body = json.loads(response.content)
        except ValueError:
            raise GraphDispatchError("MALFORMED") from None
        if not isinstance(body, dict):
            raise GraphDispatchError("MALFORMED")
        # Graph echoes the request's @odata.context on a $select; it describes the response
        # rather than the user, so it is dropped before the allowlist sees the reading.
        return {name: value for name, value in body.items() if not name.startswith("@")}

    def disable(self, user_id: str, expected: str) -> GraphDisable:
        """Read, compare against the frozen composite, and write at most once.

        A mismatch raises before any write is attempted, so a subject that moved between
        the decision and the dispatch is refused rather than disabled on stale grounds.
        """
        token = self._token()
        started = time.monotonic()
        before = self._read_user(token, user_id)
        try:
            observed = graph_user_composite(before)
        except CompositeDrift:
            # A reading this recipe was not written against is not a reading to compare.
            raise GraphDispatchError("SCHEMA_DRIFT") from None
        window_ms = max(0, int((time.monotonic() - started) * 1000))
        if observed != expected:
            # The gap is measured before the comparison decides, so a refusal reports the
            # same span an execution would have: read to the moment a write was due.
            raise GraphDispatchError(
                "VERSION_MISMATCH", observed=observed, window_ms=window_ms, status=200
            )
        try:
            response = self._client.patch(
                f"{GRAPH_ORIGIN}/v1.0/users/{user_id}",
                json={"accountEnabled": False},
                headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
                follow_redirects=False,
            )
        except httpx.HTTPError:
            # The write may or may not have landed. Saying so is the caller's business; what
            # this client must not do is send it again to find out.
            raise GraphDispatchError("INDETERMINATE") from None
        if response.status_code in {401, 403}:
            raise GraphDispatchError("FORBIDDEN")
        if response.status_code not in {200, 204}:
            raise GraphDispatchError("REFUSED")
        return GraphDisable(
            observed=observed,
            window_ms=window_ms,
            patched=True,
            status=response.status_code,
            before=dict(before),
        )
