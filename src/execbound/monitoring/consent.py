# SPDX-License-Identifier: AGPL-3.0-only
"""Connecting Microsoft Entra by verified admin consent (#228, #678).

A directory is connected to the deployment's own app, the platform app, by a consent its
administrator gives. Three steps, each bound to the one before:

1. **Start**, from an administrator's console session (`start`). The attempt is recorded with
   the SHA-256 of its OAuth `state`, of a nonce and of a binding value the starting browser
   keeps in an HttpOnly cookie, and the answer is Microsoft's sign-in address. The database
   refuses a full workspace, a space that already has an Entra connection and a tenant over its
   attempt caps before anyone leaves for Microsoft (`admin_start_connect`).
2. **Signed in** (`signed_in`), Microsoft's `form_post` of an OpenID Connect id_token. Its
   `state` must name an attempt that was started before the token is read. The token is
   verified here, RS256 against Microsoft's published keys, issued for the directory it names
   and for this app, current, and carrying a Global Administrator or Privileged Role
   Administrator role in `wids`. Only `tid` and `wids` are read: no name, address or object id,
   and no ExecBound principal is looked up, so a multi-tenant sign-in carries no risk of one
   person standing for another. The database then refuses a directory any workspace has
   connected, an update for another directory, and a workspace that filled up
   (`admin_record_signin`). Only then is the browser sent to the admin consent page.
3. **Consented** (`consented`), Microsoft's redirect back after the administrator approved. Only
   the keys Microsoft documents for it are read; the database checks every rule again and creates
   the `platform_app` connection, or records the new consent on the connection an update names
   (`admin_complete_consent`), and the change appends its audit events.

Every refusal ends a known attempt as refused with its code and the step that refused it
(`admin_refuse_connect`), and logs `monitor.connect_refused` with the code alone. The state, the
nonce, the binding value and the id_token reach no row, event or log line: the database keeps
digests, and `mc1` is a secret prefix the log guard and the export check refuse.
"""

import hashlib
import json
import re
import secrets
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from execbound.audit import append_event
from execbound.db import Database
from execbound.directory import DirectoryKeys, DirectoryRefused, verify_signature
from execbound.logging_schema import log_event
from execbound.monitoring.connect import _label, _registry, _visible
from execbound.monitoring.models import MonitorError
from execbound.monitoring.store import DEPENDENCY_ERRORS, SYSTEM_CLOCK, _session
from execbound.resolution.models import Clock
from execbound.signin import segment
from execbound.spaces import SpaceError, visible_spaces, write_space
from execbound.surfaces.sessions import Session

# Microsoft's endpoints, pinned as `oidc.py` pins Google's: no discovery document is fetched.
LOGIN_ORIGIN = "https://login.microsoftonline.com"
KEYS_URI = LOGIN_ORIGIN + "/common/discovery/v2.0/keys"
GRAPH_DEFAULT = "https://graph.microsoft.com/.default"
SIGNED_IN = "/connect/entra/signed-in"
CONSENTED = "/connect/entra/consented"
DONE = "/monitor?view=connections&connect=done"
REFUSED = "/monitor?view=connections&connect=refused"
# The two roles that can consent for a whole directory, by role template id. From Microsoft's
# built-in roles reference,
# https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference
# ("All roles"), read on 12 October 2026.
GLOBAL_ADMINISTRATOR = "62e90394-69f5-4237-9190-012177145e10"
PRIVILEGED_ROLE_ADMINISTRATOR = "e8611ab8-c189-46e8-94e1-60213ab1f814"
CONSENT_ROLES = frozenset({GLOBAL_ADMINISTRATOR, PRIVILEGED_ROLE_ADMINISTRATOR})
# The parameters of the redirect after admin consent, from Microsoft's admin consent reference,
# https://learn.microsoft.com/en-us/entra/identity-platform/v2-admin-consent, read on
# 12 October 2026: on success `admin_consent=True`, `tenant`, `scope` and `state`; on an error
# `admin_consent`, `error`, `error_description` and `state`. The reference documents no
# `error_uri` or `error_subcode` here, so neither is read: like any other key Microsoft may add,
# each is ignored and never logged.
CONSENT_KEYS = frozenset(
    {"admin_consent", "tenant", "scope", "state", "error", "error_description"}
)
# What Microsoft's form_post of an id_token carries, and the same page's error.
SIGN_IN_KEYS = frozenset({"id_token", "state", "error", "error_description"})
MAX_SCOPE = 2048
MAX_TOKEN = 16384
MAX_SKEW = 300
GUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
STATE = re.compile(
    r"mc1\.(?P<tenant>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
    r"\.(?P<attempt>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
    r"\.[A-Za-z0-9_-]{43}"
)
# What `admin_refuse_connect` accepts as a refusal code.
CODE = re.compile(r"[A-Z_]{1,48}")
# The definer functions' refusals at the start, each to the code a caller sees.
_START_REFUSALS = {
    "INVALID_TENANT": "INVALID_ADMIN",
    "INVALID_ACTOR": "INVALID_ADMIN",
    "INVALID_SPACE": "SPACE_REQUIRED",
    "SPACE_ARCHIVED": "SPACE_ARCHIVED",
    "CONNECTION_CAPACITY": "CONNECTION_CAPACITY",
    "CONNECTION_EXISTS": "CONNECTION_EXISTS",
    "ATTEMPT_CAPACITY": "ATTEMPT_CAPACITY",
    "INVALID_STATE": "CONNECTION_REVOKED",
    "INVALID_INPUT": "INVALID_INPUT",
}


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()


def _message(exc: DBAPIError) -> str:
    diagnostic = getattr(exc.orig, "diag", None)
    return str(getattr(diagnostic, "message_primary", None) or "")


def _code(exc: DBAPIError) -> str:
    """The code a definer function raised, or `UNAVAILABLE` for anything else the database
    said: a lock or statement timeout, a constraint it re-raised. Those are worded for people,
    and only a code is recorded on an attempt or logged."""
    message = _message(exc)
    return message if CODE.fullmatch(message) is not None else "UNAVAILABLE"


@dataclass(frozen=True)
class Started:
    """Where the browser goes to sign in, and the value its binding cookie holds."""

    authorize_url: str = field(repr=False)
    binding: str = field(repr=False)


def start(
    db: Database,
    session: Session,
    *,
    client_id: str,
    authority: str,
    origin: str,
    label: str | None = None,
    connection_id: UUID | None = None,
    clock: Clock = SYSTEM_CLOCK,
) -> Started:
    """Record one attempt to connect a directory, by its `label`, or to update the consent of
    the connection `connection_id` names, and answer Microsoft's sign-in address for it."""
    if (label is None) == (connection_id is None):
        raise MonitorError("INVALID_INPUT")
    name = _label(label) if label is not None else None
    identity = session.identity
    attempt = uuid4()
    state = f"mc1.{identity.tenant_id}.{attempt}.{secrets.token_urlsafe(32)}"
    nonce = secrets.token_urlsafe(32)
    binding = secrets.token_urlsafe(32)
    try:
        with db.transaction(identity.tenant_id) as conn:
            _session(conn, session, clock)
            _registry(conn, identity.tenant_id)
            if connection_id is None:
                try:
                    space = write_space(conn, identity.tenant_id, visible_spaces(conn, session))
                except SpaceError:
                    raise MonitorError("SPACE_REQUIRED") from None
            else:
                row = _visible(conn, session, connection_id)
                if row["kind"] != "entra_agent_id" or row["credential_mode"] != "platform_app":
                    raise MonitorError("CONNECTION_NOT_CONSENTED")
                space = row["space_id"]
            conn.execute(
                text(
                    "SELECT execbound.admin_start_connect(:a, :s, :attempt, :c, :label, "
                    ":state, :binding, :nonce)"
                ),
                {
                    "a": identity.principal_id,
                    "s": space,
                    "attempt": attempt,
                    "c": connection_id,
                    "label": name,
                    "state": _digest(state),
                    "binding": _digest(binding),
                    "nonce": _digest(nonce),
                },
            )
            _session(conn, session, clock)
    except DBAPIError as exc:
        raise MonitorError(_START_REFUSALS.get(_message(exc), "MONITOR_UNAVAILABLE")) from None
    except DEPENDENCY_ERRORS:
        raise MonitorError() from None
    query = urlencode(
        {
            "client_id": client_id,
            "response_type": "id_token",
            "response_mode": "form_post",
            "scope": "openid",
            "redirect_uri": origin.rstrip("/") + SIGNED_IN,
            "state": state,
            "nonce": nonce,
            "prompt": "select_account",
        }
    )
    return Started(f"{LOGIN_ORIGIN}/{authority}/oauth2/v2.0/authorize?{query}", binding)


class ConnectRefused(Exception):
    """A refused callback; the code is for the log, never the page."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class _Attempt:
    """The attempt a callback's `state` names, and the fence that state sets."""

    tenant: UUID
    attempt: UUID
    state_hash: str = field(repr=False)


def _attempt(state: object) -> _Attempt | None:
    if type(state) is not str or len(state) > 160:
        return None
    found = STATE.fullmatch(state)
    if found is None:
        return None
    return _Attempt(UUID(found["tenant"]), UUID(found["attempt"]), _digest(state))


def _refuse(db: Database, attempt: _Attempt | None, step: str, code: str) -> ConnectRefused:
    """End a known attempt as refused, with its code and step, and log the code alone. The
    attempt is found under the fence its own state names, so a state rewritten to name another
    workspace ends nothing there."""
    if attempt is not None:
        try:
            with db.transaction(attempt.tenant) as conn:
                conn.execute(
                    text("SELECT execbound.admin_refuse_connect(:a, :state, :step, :code)"),
                    {"a": attempt.attempt, "state": attempt.state_hash, "step": step, "code": code},
                )
        except (DBAPIError, *DEPENDENCY_ERRORS):
            # The refusal stands whether or not it could be written down: nothing was created.
            pass
    log_event("monitor.connect_refused", level="WARNING", code=code)
    return ConnectRefused(code)


def _named(pairs: Sequence[tuple[str, str]], names: frozenset[str]) -> tuple[dict[str, str], bool]:
    """The documented keys, the first of each, and whether any was repeated. Every other key
    is ignored and never read: a provider may add parameters, and refusing an unknown one would
    refuse a real answer while ignoring it grants nothing."""
    values: dict[str, str] = {}
    repeated = False
    for key, value in pairs:
        if key not in names:
            continue
        if key in values:
            repeated = True
            continue
        values[key] = value
    return values, repeated


def _claims(token: object, keys: DirectoryKeys, client_id: str, now: float) -> dict[str, Any]:
    """An id_token's claims once its signature, issuer, audience and times hold. RS256 only,
    and only Microsoft's published keys. Each failure is its own code."""
    if type(token) is not str or not 0 < len(token) <= MAX_TOKEN:
        raise ConnectRefused("INVALID_TOKEN")
    pieces = token.split(".")
    if len(pieces) != 3:
        raise ConnectRefused("INVALID_TOKEN")
    try:
        header = json.loads(segment(pieces[0]).decode("utf-8"))
        payload = json.loads(segment(pieces[1]).decode("utf-8"))
        signature = segment(pieces[2]) if pieces[2] else b""
    except (ValueError, UnicodeDecodeError):
        raise ConnectRefused("INVALID_TOKEN") from None
    if type(header) is not dict or type(payload) is not dict:
        raise ConnectRefused("INVALID_TOKEN")
    if header.get("alg") != "RS256":
        raise ConnectRefused("INVALID_ALGORITHM")
    kid = header.get("kid")
    if type(kid) is not str or not kid:
        raise ConnectRefused("INVALID_TOKEN")
    # Only an RSA key is looked up for RS256, so a key of another type Microsoft's set might
    # publish under this `kid` is never found, and never reaches the signature check.
    try:
        key = keys.key(kid, "RS256")
    except DirectoryRefused as refused:
        raise ConnectRefused(refused.code) from None
    try:
        verify_signature(key, "RS256", f"{pieces[0]}.{pieces[1]}".encode("ascii"), signature)
    except DirectoryRefused:
        raise ConnectRefused("INVALID_SIGNATURE") from None
    tenant = payload.get("tid")
    if type(tenant) is not str or GUID.fullmatch(tenant.lower()) is None:
        raise ConnectRefused("INVALID_DIRECTORY")
    # The issuer of the token's own directory, exactly; the shared `organizations` issuer is
    # never one, because a token always names the directory that signed the person in.
    if payload.get("iss") != f"{LOGIN_ORIGIN}/{tenant}/v2.0":
        raise ConnectRefused("INVALID_ISSUER")
    audience = payload.get("aud")
    if audience != client_id and audience != [client_id]:
        raise ConnectRefused("INVALID_AUDIENCE")
    expiry, valid_from, issued = payload.get("exp"), payload.get("nbf"), payload.get("iat")
    if (
        type(expiry) is not int
        or type(issued) is not int
        or (valid_from is not None and type(valid_from) is not int)
        or expiry + MAX_SKEW <= now
        or issued > now + MAX_SKEW
        or (valid_from is not None and valid_from > now + MAX_SKEW)
    ):
        raise ConnectRefused("INVALID_TIME")
    roles = payload.get("wids")
    if type(roles) is not list or not CONSENT_ROLES & {role for role in roles if type(role) is str}:
        raise ConnectRefused("NO_ADMIN_ROLE")
    nonce = payload.get("nonce")
    if type(nonce) is not str or not 0 < len(nonce) <= 256:
        raise ConnectRefused("NONCE_MISMATCH")
    return {"tid": tenant.lower(), "nonce": nonce}


def signed_in(
    db: Database,
    keys: DirectoryKeys,
    *,
    client_id: str,
    authority: str,
    origin: str,
    request_origin: str | None,
    pairs: Sequence[tuple[str, str]],
    binding: str | None,
    now: float,
) -> str:
    """Microsoft's form_post of the administrator's id_token: the admin consent address for the
    directory it verified, or `ConnectRefused` once the attempt is ended."""
    values, repeated = _named(pairs, SIGN_IN_KEYS)
    attempt = _attempt(values.get("state"))
    step = "signed_in"
    # Microsoft posts this form from its own origin and from nowhere else.
    if request_origin != LOGIN_ORIGIN:
        raise _refuse(db, attempt, step, "INVALID_ORIGIN")
    if attempt is None:
        raise _refuse(db, None, step, "INVALID_STATE")
    if repeated:
        raise _refuse(db, attempt, step, "REPEATED_PARAMETER")
    if "error" in values:
        raise _refuse(db, attempt, step, "PROVIDER_ERROR")
    if not binding:
        raise _refuse(db, attempt, step, "BINDING_MISSING")
    # Only a state some attempt was started with reaches the token, so a forged one cannot make
    # this server fetch Microsoft's keys. Whether that attempt is still live is the database's
    # to decide below, with its own code.
    try:
        with db.transaction(attempt.tenant) as conn:
            known = conn.execute(
                text(
                    "SELECT EXISTS (SELECT 1 FROM execbound.monitor_connect_attempts "
                    "WHERE tenant_id = :t AND attempt_id = :a AND state_hash = :state)"
                ),
                {"t": attempt.tenant, "a": attempt.attempt, "state": attempt.state_hash},
            ).scalar_one()
    except (DBAPIError, *DEPENDENCY_ERRORS):
        raise _refuse(db, attempt, step, "UNAVAILABLE") from None
    if known is not True:
        raise _refuse(db, attempt, step, "INVALID_STATE")
    try:
        claims = _claims(values.get("id_token"), keys, client_id, now)
    except ConnectRefused as refused:
        raise _refuse(db, attempt, step, refused.code) from None
    directory = claims["tid"]
    # A single-tenant registration consents for its own directory and no other.
    if authority != "organizations" and directory != authority.lower():
        raise _refuse(db, attempt, step, "INVALID_DIRECTORY")
    try:
        with db.transaction(attempt.tenant) as conn:
            conn.execute(
                text(
                    "SELECT execbound.admin_record_signin(:a, :state, :binding, :nonce, :directory)"
                ),
                {
                    "a": attempt.attempt,
                    "state": attempt.state_hash,
                    "binding": _digest(binding),
                    "nonce": _digest(claims["nonce"]),
                    "directory": directory,
                },
            )
    except DBAPIError as exc:
        raise _refuse(db, attempt, step, _code(exc)) from None
    except DEPENDENCY_ERRORS:
        raise _refuse(db, attempt, step, "UNAVAILABLE") from None
    query = urlencode(
        {
            "client_id": client_id,
            "scope": GRAPH_DEFAULT,
            "redirect_uri": origin.rstrip("/") + CONSENTED,
            "state": values["state"],
        }
    )
    return f"{LOGIN_ORIGIN}/{directory}/v2.0/adminconsent?{query}"


def consented(
    db: Database,
    *,
    client_id: str,
    pairs: Sequence[tuple[str, str]],
    binding: str | None,
) -> UUID:
    """Microsoft's redirect after the administrator approved: the connection the consent
    created or updated, or `ConnectRefused` once the attempt is ended."""
    values, repeated = _named(pairs, CONSENT_KEYS)
    attempt = _attempt(values.get("state"))
    step = "consented"
    if attempt is None:
        raise _refuse(db, None, step, "INVALID_STATE")
    if repeated:
        raise _refuse(db, attempt, step, "REPEATED_PARAMETER")
    # The error keys are read for presence only, never their values.
    if "error" in values:
        raise _refuse(db, attempt, step, "PROVIDER_ERROR")
    if not binding:
        raise _refuse(db, attempt, step, "BINDING_MISSING")
    if values.get("admin_consent") != "True":
        raise _refuse(db, attempt, step, "CONSENT_NOT_GRANTED")
    directory = values.get("tenant", "").lower()
    if GUID.fullmatch(directory) is None:
        raise _refuse(db, attempt, step, "DIRECTORY_MISMATCH")
    # Read for presence and length only, never kept or logged: the probe, not this value,
    # decides which permissions hold.
    scope = values.get("scope")
    if scope is None or not 0 < len(scope) <= MAX_SCOPE:
        raise _refuse(db, attempt, step, "INVALID_SCOPE")
    try:
        with db.transaction(attempt.tenant) as conn:
            connection_id = conn.execute(
                text(
                    "SELECT execbound.admin_complete_consent(:a, :state, :binding, "
                    ":directory, :client)"
                ),
                {
                    "a": attempt.attempt,
                    "state": attempt.state_hash,
                    "binding": _digest(binding),
                    "directory": directory,
                    "client": client_id,
                },
            ).scalar_one()
            _recorded(conn, attempt, connection_id, directory)
    except DBAPIError as exc:
        raise _refuse(db, attempt, step, _code(exc)) from None
    except DEPENDENCY_ERRORS:
        raise _refuse(db, attempt, step, "UNAVAILABLE") from None
    return UUID(str(connection_id))


def _recorded(conn: Any, attempt: _Attempt, connection_id: UUID, directory: str) -> None:
    """The audit events of a completed consent, as the last writes of its transaction: a new
    connection's creation, and the consent itself. The actor is the attempt's principal, the
    administrator who started it; the callback carries no session, so no credential is named,
    and the attempt is, which records which browser bound it."""
    row = (
        conn.execute(
            text(
                "SELECT principal_id, space_id, label FROM execbound.monitor_connect_attempts "
                "WHERE tenant_id = :t AND attempt_id = :a"
            ),
            {"t": attempt.tenant, "a": attempt.attempt},
        )
        .mappings()
        .one()
    )
    if row["label"] is not None:
        append_event(
            conn,
            attempt.tenant,
            row["principal_id"],
            "monitor.connection_created",
            {
                "connection_id": str(connection_id),
                "space_id": str(row["space_id"]),
                "kind": "entra_agent_id",
                "credential_mode": "platform_app",
                "label": row["label"],
                "attempt_id": str(attempt.attempt),
            },
            space=row["space_id"],
        )
    append_event(
        conn,
        attempt.tenant,
        row["principal_id"],
        "monitor.consent_recorded",
        {
            "connection_id": str(connection_id),
            "directory_ref": directory,
            "attempt_id": str(attempt.attempt),
        },
        space=row["space_id"],
    )


def last_attempt(
    db: Database, session: Session, *, clock: Clock = SYSTEM_CLOCK
) -> Mapping[str, Any] | None:
    """The session's own principal's latest attempt, if it ended within the last ten minutes:
    whether it was consented or refused, whether Microsoft may already hold a consent, and the
    connection it made. Never another principal's attempt, and never a code."""
    identity = session.identity
    try:
        with db.transaction(identity.tenant_id) as conn:
            _session(conn, session, clock)
            row = (
                conn.execute(
                    text(
                        "SELECT state, refused_step, connection_id "
                        "FROM execbound.monitor_connect_attempts "
                        "WHERE tenant_id = :t AND principal_id = :p "
                        "AND state IN ('consented', 'refused') "
                        "AND consumed_at > CAST(:now AS timestamptz) - interval '10 minutes' "
                        "ORDER BY consumed_at DESC LIMIT 1"
                    ),
                    {
                        "t": identity.tenant_id,
                        "p": identity.principal_id,
                        "now": clock.now(),
                    },
                )
                .mappings()
                .one_or_none()
            )
    except DEPENDENCY_ERRORS:
        raise MonitorError() from None
    if row is None:
        return None
    return {
        "outcome": row["state"],
        "refused_after_consent": row["refused_step"] == "consented",
        "connection_id": row["connection_id"],
    }
