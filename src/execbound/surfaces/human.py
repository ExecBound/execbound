# SPDX-License-Identifier: AGPL-3.0-only
"""Scoped browser sessions and server-rendered decisions over frozen execution records."""

import base64
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import parse_qsl, urlsplit
from uuid import UUID

import anyio
import httpx
from fastapi import APIRouter, HTTPException, Request
from jinja2 import Environment, PackageLoader, StrictUndefined
from sqlalchemy import text
from sqlalchemy.engine import Connection
from starlette.concurrency import run_in_threadpool
from starlette.responses import HTMLResponse, RedirectResponse, Response

from execbound.contracts import Catalog, ContractError
from execbound.directory import DirectoryConfig
from execbound.envelope import KeyRing
from execbound.execution import _correctable, decide_approval, reconcile, store
from execbound.execution.models import (
    ACT_WINDOW,
    UNSETTLED,
    AuthorityCheck,
    ExecutionError,
    ExecutionView,
    PreconditionConfig,
    StopState,
)
from execbound.identity import AuthenticationFailed, authenticate, record_failure
from execbound.logging_schema import log_event
from execbound.monitoring.sealing import CollectorPublicKey
from execbound.notifications import delivery_times
from execbound.notifications import summary as notification_summary
from execbound.operations import PRODUCTION_ACTIONS, CatalogError
from execbound.passwords import SIGN_IN_LIFETIME
from execbound.plugins import ApprovalLinks
from execbound.policy.models import LimitRule
from execbound.resolution.models import ResolvedRequest
from execbound.runtime import Runtime
from execbound.service_links import ServiceLinks
from execbound.signin import SignInProvider
from execbound.spaces import space_clause, visible_spaces
from execbound.surfaces import outcomes
from execbound.surfaces.http import IDENTITY_HEADERS, client_key, identity_for
from execbound.surfaces.limits import RateLimited, credential_selector
from execbound.surfaces.login_return import (
    canonical,
    destination,
    login_location,
    remember,
    remember_path,
)
from execbound.surfaces.names import principal_facts
from execbound.surfaces.sessions import (
    Session,
    SessionError,
    SessionGrant,
    check_session,
    device_label,
    issue_session,
    revoke_session,
    verify_csrf,
)
from execbound.surfaces.tokens import (
    Audience,
    Continuation,
    InvalidContinuation,
    TokenKeys,
    sign,
    verify,
)


@dataclass(frozen=True)
class ScoutEntra:
    """The platform app a directory administrator consents to (#678): its client id, the
    authority its sign-in uses (`organizations`, or one directory's id for a single-tenant
    registration) and the name the administrator sees for it under Enterprise applications.
    Every value is public; the app's certificate lives in the collector's environment alone."""

    client_id: str
    authority: str
    display_name: str
    # How the consent reaches Microsoft's signing keys; a test injects its fake here.
    http: httpx.Client | None = field(default=None, repr=False, compare=False)


@dataclass(frozen=True)
class ScoutConfig:
    """Monitoring connected from the console, from the runtime configuration's `scout` block
    (#678): the collector's public key, which the gateway seals a pasted key to, and, where
    Microsoft Entra can be connected by consent, the platform app's public values. It holds no
    key that opens a sealed one and nothing that signs for the app; those live in the
    collector's environment alone."""

    collector: CollectorPublicKey | None = None
    entra: ScoutEntra | None = None


def check_origin(origin: str) -> None:
    """Hold a deployment's origin to the console's rule: https, or http on a loopback address,
    with a host and nothing after it. `HumanConfig` and `configuration.read_outbound`, which
    builds every finding's link from it (#31), read this one rule; `read_outbound` also holds
    the origin to the finding message's narrower one (`transports.is_message_origin`)."""
    parsed = urlsplit(origin)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Invalid application origin")
    if parsed.scheme == "http":
        try:
            if not ipaddress.ip_address(parsed.hostname).is_loopback:
                raise ValueError
        except ValueError:
            raise ValueError("Cleartext application origin must use a loopback IP") from None
    _ = parsed.port


@dataclass(frozen=True)
class HumanConfig:
    origin: str
    keys: TokenKeys
    assistant_enabled: bool = False
    """Whether the private configuration carries an `assistant` block; without it the
    assistant's routes do not exist (#330). A tenant's own switch is a row, not this flag."""
    providers: tuple[SignInProvider, ...] = ()
    """The sign-in providers this deployment was configured with, in a fixed order.

    A provider with no block in the private configuration is absent from this tuple, shows
    no button on `/login` and answers on neither of its routes. It is deployment
    configuration and reaches no request: nothing a caller sends can choose a client id, a
    redirect URI or a provider that was not configured."""

    directory: DirectoryConfig | None = None
    """The key ring a customer's own identity provider needs, or None (#177, #241).

    A tenant's provider is a row rather than a block here, but its client secret has to be kept
    somewhere, and a deployment given no ring has nowhere to keep one: with this absent no
    tenant can register a directory, the console says so instead of offering a form that cannot
    work, and the routes answer 404. Absence is the switch, exactly as it is for the providers
    above."""

    mfa: KeyRing | None = None

    scout: ScoutConfig | None = None
    """Console connect for monitoring, or None where the deployment has not configured it: the
    console then says who connects a provider instead of offering a form that cannot work."""

    service: ServiceLinks = ServiceLinks()
    """The deployment's support address and public pages, from its runtime configuration's
    `service` block or a loaded plugin, never both (`LoadedPlugins.service`). Every page's
    footer, the sign-in page, the MFA pages and the console's session read it here, and a link
    it gives no address for is not shown. `ServiceLinks()`, none at all, is the default."""

    def provider(self, name: str) -> SignInProvider | None:
        return next((item for item in self.providers if item.name == name), None)

    def rotate(self, keys: TokenKeys) -> None:
        """Swap the form-state ring; a form loaded under a retained key still submits."""
        if type(keys) is not TokenKeys:
            raise ValueError("Invalid continuation keys")
        object.__setattr__(self, "keys", keys)

    def __post_init__(self) -> None:
        check_origin(self.origin)
        if type(self.service) is not ServiceLinks or not self.service.valid():
            raise ValueError("Invalid service links")

    @property
    def secure(self) -> bool:
        return self.origin.startswith("https://")

    def cookie(self, name: str) -> str:
        return ("__Host-" if self.secure else "") + "eb_" + name


def resource_class(frozen: ResolvedRequest, catalog: Catalog) -> str | int | bool:
    """Contract-selected display value; templates still escape it as untrusted text."""
    try:
        contract = catalog.contract(frozen.context_contract_version)
    except ContractError:
        # A frozen plan can name a contract this runtime's catalog lacks. Keep the
        # tenant's listing readable instead of failing every row.
        return "unknown contract " + frozen.context_contract_version
    return frozen.fact(contract.display_fact).value


def action_label(frozen: ResolvedRequest, catalog: Catalog) -> str:
    """Catalog-selected display label; templates still escape it as untrusted text."""
    try:
        return catalog.actions.action(frozen.intent.action).label
    except CatalogError:
        # A frozen plan can name an action this runtime's catalog lacks. Keep the
        # tenant's listing readable instead of failing every row.
        return "unknown action " + frozen.intent.action


def environment_label(frozen: ResolvedRequest) -> str | int | bool | None:
    return next((fact.value for fact in frozen.facts if fact.name == "environment"), None)


def limit_label(rule: LimitRule, names: Mapping[UUID, str]) -> str:
    """Scope text for a rule; group names, ids and fact values are untrusted data."""
    # Only the leading word is capitalized here; a template filter would lowercase the
    # rest of a group name or a fact value, which are shown exactly as retained.
    if rule.scope == "group" and rule.group_id is not None:
        return "Group " + names.get(rule.group_id, str(rule.group_id))
    if rule.scope == "account" and rule.account_id is not None:
        return f"Account {rule.account_id}"
    if rule.selector is not None:
        value = rule.selector.equals
        # Booleans read like the arguments block, never Python's True/False.
        shown = ("true" if value else "false") if type(value) is bool else str(value)
        fact = rule.selector.fact
        return f"{fact[:1].upper()}{fact[1:]} = {shown}"
    return rule.scope[:1].upper() + rule.scope[1:]


# What the record and approval pages say about an operation ExecBound decided and did not
# dispatch. Every sentence below is inert text, rendered through the autoescaping
# templates like any other: none of it is a control and none of it changes a record. The
# two classifications a checkpoint carries are statements about what ExecBound could
# check — the precondition class about the vendor's API as a deployment declares it, the
# evidence tier about the report ExecBound was sent — and neither is a claim about what
# happened at the vendor.
EXTERNALLY_EXECUTED = (
    "Externally executed: the bundle mapping this request was admitted under names an "
    "external executor, so ExecBound decided it and dispatched nothing. The executor holds "
    "the vendor credential and acts on its own. The precondition class is what a deployment "
    "declares the vendor's API can check and the evidence tier is what ExecBound could check "
    "about a report it was sent; neither is a claim about what happened at the vendor."
)
# Whether a grant was issued for this record. `dispatch_attempted_at` is the mark:
# `admission._admit` stamps it in the transaction that commits the grant, and
# `dispatch.take_dispatch`, the only other statement in the source that writes the column,
# refuses a row carrying a report window, so no dispatch stamps a labelled row. The state
# alone does not say it. STALE_AUTHORIZATION is reachable from a committed grant and from
# a pending approval, and a settled checkpoint whose executor reported a version mismatch
# is one of the first; `test_a_settled_stale_checkpoint_says_a_grant_was_issued` and
# `test_a_refused_checkpoint_says_no_grant_was_issued_and_offers_no_control` hold both
# directions on real rows.
_GRANT_OUTSTANDING = "Issued. Nothing has recorded an outcome for it."
_GRANT_UNSETTLED = "Issued. Nothing has settled it."
_GRANT_SETTLED = "Issued and settled."
_NOT_ISSUED_TEXT = {
    "PENDING_APPROVAL": (
        "None yet. One is issued only if a human approves and the caller asks again."
    ),
    "DENIED": "None. The decision refused this request.",
}
# Every other state an unstamped row carrying a report window can be read in. It says what
# is outstanding rather than what was issued, because the absence of the stamp is not a
# history: `dispatch_attempted_at` is in `db.UPDATE_COLUMNS`, and a row whose stamp is gone
# — the shape `tests/checkpoint_fixtures.clear_attempt` writes over the owner connection,
# which no runtime path produces — would otherwise be told no grant ever existed for it.
_NO_GRANT_TEXT = "None outstanding for this record."
# A class is a property of the grant it was issued with, not of the record. Admission
# reads the declaration in force at that moment and hands the class to the executor, and
# nothing declared afterwards changes the grant already in that executor's hands, so a
# page reading this deployment's configuration can describe an issued grant with a
# guarantee it does not carry. The class is therefore shown from configuration for exactly
# the two states in which no grant has been issued — the pending approval an approver weighs
# it on, and the refusal — and worded there as a declaration about the binding rather than
# as a protection the record enjoys. Every other record gets `_PRECONDITION_RETAINED`, which
# names where the class is kept: `admission._grant` appends it to the
# execution.checkpoint_granted event, once for the grant and once for each later answer
# describing it again, so what each answer carried is retained beside that answer. The first
# answer also writes it to `executions.precondition_class`, for the outcome route, and a
# later answer is described under that recorded class; no page reads that column for a
# grant, and a grant an earlier version issued has nothing there.
_CLASS_STATES = frozenset({"PENDING_APPROVAL", "DENIED"})
_PRECONDITION_TEXT = {
    "ENFORCED_BY_PROVIDER": (
        "Enforced by the provider, as this deployment declares this binding: the vendor "
        "offers a conditional write and an executor must use it, so a grant issued for "
        "this record would carry a version and a change before the action would fail it."
    ),
    "ASSERTED_BY_EXECUTOR": (
        "Asserted by the executor, as this deployment declares this binding: the vendor "
        "exposes a version but no conditional write, so a grant issued for this record "
        "would carry a version its executor could only compare, and a mismatch would be "
        "the executor's own word about a race it observed."
    ),
    "CHECKED_BY_CONNECTOR": (
        "Checked by the connector, as this deployment declares this binding: the vendor "
        "offers no conditional write, and ExecBound's own connector reads the state and "
        "compares it immediately before writing. That is this deployment's own "
        "observation rather than atomicity, and it belongs to actions ExecBound "
        "dispatches itself. This record would be executed externally, so no grant can be "
        "issued for it under this declaration and one would be refused: a grant carrying "
        "this class would credit an executor with a check ExecBound never made for it."
    ),
    "UNAVAILABLE": (
        "Unavailable, as this deployment declares this binding: the vendor expresses no "
        "version, so a grant issued for this record would carry none and a change before "
        "the action would be undetectable."
    ),
}
# What a dispatch ExecBound made actually carried, as opposed to what this deployment
# declares for the binding now. The two are different statements and must not share
# wording: `_PRECONDITION_TEXT` above describes a declaration in force, for a record no
# grant has been issued for, and can change after the fact; these describe one attempt,
# read from the class `take_dispatch` stamped on the row when it consumed the send
# attempt, which nothing declared afterwards revises.
_DISPATCHED_PRECONDITION = {
    "ENFORCED_BY_PROVIDER": (
        "Enforced by the provider: this dispatch carried the frozen expected version to a "
        "vendor that offers a conditional write, so a change to the target before the "
        "action would have failed it at the vendor."
    ),
    "CHECKED_BY_CONNECTOR": (
        "Checked by the connector: the vendor offers no conditional write, so ExecBound "
        "read the target's state and compared it immediately before writing. That is "
        "ExecBound's own check and not atomicity — a change landing between the read and "
        "the write is not detectable, and the gap is recorded beside this record rather "
        "than claimed to be nothing."
    ),
    "ASSERTED_BY_EXECUTOR": (
        "Asserted by the executor: the class this binding is declared with belongs to an "
        "externally executed operation, and a record ExecBound dispatched itself carrying "
        "it is a misconfiguration worth reading as one."
    ),
    "UNAVAILABLE": (
        "None: this deployment declared nothing for the binding, so this dispatch carried "
        "no precondition anything could check and a change before the action would have "
        "been undetectable."
    ),
}
# A row dispatched before the class was recorded at all. Every provider then was a mock
# that refuses a mutation whose version has moved, so this is what the dispatch had; it is
# said as history rather than stamped on the row, because the row was never declared.
_PRECONDITION_BEFORE_RECORDING = (
    "Enforced by the provider. This dispatch predates the recording of a precondition "
    "class, when every configured provider was a mock that refuses a mutation whose "
    "expected version has moved."
)
_PRECONDITION_UNDISPATCHED = "Not yet: no send attempt has been made for this record."


# The measured gap, said as a measurement with its unit, so a reader weighs a number
# rather than reading an adjective. It is never a threshold: a wide window is evidence,
# and refusing on it would invent the guarantee the class exists to deny.
_PRECONDITION_WINDOW = (
    " The gap between that read and the write was {} milliseconds, measured and retained."
)


def dispatched_precondition(row: Mapping[str, Any]) -> str:
    """One finished sentence about what this record's own dispatch carried."""
    if row.get("dispatch_attempted_at") is None:
        return _PRECONDITION_UNDISPATCHED
    declared = row.get("precondition_class")
    if declared is None:
        return _PRECONDITION_BEFORE_RECORDING
    sentence = _DISPATCHED_PRECONDITION[declared]
    window = row.get("precondition_window_ms")
    # Only the class that measures a gap can show one, and only when it was measured. A
    # window shown beside any other class would credit a check nothing made.
    if declared == "CHECKED_BY_CONNECTOR" and type(window) is int and not isinstance(window, bool):
        sentence += _PRECONDITION_WINDOW.format(window)
    return sentence


_PRECONDITION_RETAINED = (
    "Not shown for this record. A grant carries the class this deployment declared when "
    "admission issued it, and nothing declared afterwards changes the grant already in an "
    "executor's hands, so this page does not describe an issued grant by the declaration "
    "in force now. The class each answer carried is retained beside it, in this record's "
    "execution.checkpoint_granted audit events."
)
# The report window, paired with the grant and with the settlement like every other label.
# Unstamped, the instant is not a deadline for anything and is not printed: it is written
# before the decision for every request the mapping would have granted, so a refused row
# would otherwise show a human a future report deadline, which is the marker read as a
# live grant in the one place a human reads it.
_REPORT_OPEN = "Open until {}. A report presented after that is refused."
_REPORT_CLOSED = "Closed {}. A report presented now is refused."
_REPORT_SETTLED = "Closed: this record is already settled, and a later report settles nothing."
_REPORT_UNUSED = (
    "None. The window is stamped before the decision for every request this mapping would "
    "have granted, and this record has no grant a report could settle."
)
_TIER_TEXT = {
    "ATTESTED": (
        "Attested: ExecBound verified the executor's signature against a key an "
        "administrator registered. That authenticates who spoke; it proves no vendor effect."
    ),
    "ASSERTED": (
        "Asserted: the executor's authenticated word, with nothing ExecBound could check."
    ),
    "PROVIDER_VERIFIED": (
        "Provider verified: ExecBound verified a journal the provider signed for this exact "
        "command, under a key this deployment configured. A party other than the executor "
        "recorded the vendor's own result."
    ),
}
_CLAIM_HELD = (
    "Held: no other ExecBound request in this tenant can claim this target while it stands."
)
_NO_CLAIM = "None was taken for this record."
# Why a settled assertion still holds a target, said on the row itself, because nothing
# else on the page says it. Two kinds of settled row reach this sentence and they are told
# apart below: a `_correctable` one, which `can_reconcile` now offers the correction, and
# a settled assertion that is not one, which `reconciliation._unsettled_grant_only` refuses
# a second settlement of. The continuation a rendered control carries binds the record and
# not the state it was read in, so which of the two a row is is decided again at the POST.
_ASSERTION_HOLDS = (
    "An assertion never releases a canonical claim, and this record is already settled. "
)
# The sentences below are about a control, so they are said only to the reader who is
# offered controls at all. `can_reconcile` requires ADMIN; an approver is offered no
# settlement control on any row in any state, so telling one what a control here does, or
# that none is offered, describes a page that does not exist for it.
#
# The correction sentence stands beside a control the page is rendering, so it says what
# that control does to this record rather than naming the kernel function behind it. Each
# clause is a refusal something already makes: the evidence must be a record a verifier
# returned and its outcome a non-execution, refused otherwise by
# `reconciliation._unsettled_grant_only` and by `outcomes._settle`'s own direction test; and
# a corrected row holds none of `_correctable`'s three facts and `models._TRANSITIONS` holds
# no key for the state it now carries, so a second correction of it is refused twice over.
_CORRECTION_CONTROL = (
    "The control below corrects this settlement rather than reopening the record: a "
    "record signed by an executor key this tenant registered, stating that the call was "
    "not executed, replaces the platform's unchecked word with evidence ExecBound can "
    "check, refunds the impact and releases the claim. A record stating that the executor "
    "acted is refused here, and a corrected record is refused a second correction. "
)
# What the other settled assertions get instead, which is what this sentence said for every
# settled row before the correction existed.
_NO_SETTLEMENT_CONTROL = (
    "No settlement control is offered for this record, and a second settlement of it is refused. "
)
# Named as the recovery run's own earliest boundary and not as a release time. The run
# selects on `dispatch_attempted_at + ACT_WINDOW` and also on `changed_at` being older
# than its grace period, so this instant is necessary and not sufficient — and for a
# report arriving more than the grace period after the grant, which is the ordinary case,
# it is already in the past when the page prints it.
_SWEEP_RELEASES = (
    "The scheduled recovery run is what releases the claim: it selects no record before "
    "{}, and none that changed more recently than its grace period, so that instant is "
    "the earliest a release can happen rather than when it will."
)
_SWEEP_WAITS = (
    "The scheduled recovery run measures that from the attempt time this record no longer "
    "carries, so it releases nothing here."
)
# The state a control point's own word settles a grant at. It is a settled state whose
# evidence is nobody's but the reporter's, so the page says what was and was not
# established rather than leaving a reader to infer it from a state name.
REPORTED_FAILURE_STATE = "FAILED_EFFECT_UNKNOWN"
_EFFECT_UNKNOWN = (
    "The effect was never established. The executor stated that its call failed and "
    "ExecBound could check nothing about that statement, so this record says what was "
    "reported and not what the vendor did. The impact is charged exactly as a reported "
    "success is charged, because closing a record on an unverifiable statement must not "
    "be cheaper than stating the opposite."
)
# A corrected row's own `result` column holds the correcting evidence alone —
# `execution.outcomes._settle` replaces it — so the statement the correction replaced
# survives in the transition history and nowhere else on the record. That is why this
# sentence names its source: a reader who goes looking for the earlier statement in the
# retained result will not find it there.
_CORRECTION = (
    "Corrected: this record was settled once on the executor's word that its call failed, "
    "and a verified non-execution replaced that settlement. What the record retains is the "
    "correcting evidence alone, so the statement it replaced is read from this record's "
    "transition history rather than from the record — {}"
)
_STATEMENT = "the executor stated {} for reason {}, on its own clock at {}."
_STATEMENT_ABSENT = (
    "the history records the settlement it replaced and retains no statement with it."
)
# What a control point's hook retained about one tool call. None of it decided anything:
# the action, the target and the decision came from the operator's tool map, the frozen
# plan and the active bundle, and `arcade.store` writes these columns for an operator to
# read Arcade's own log beside ExecBound's. A human page treats an agent's and a
# provider's strings as untrusted data, which here means the templates escape every one of
# them and no control on either page acts on any of them.
CONTROL_POINT_CARRIED = (
    "Carried by a control point: an Arcade hook opened this record, and the tool identity, "
    "the end user and the reported result below are the platform's own strings. ExecBound "
    "checked none of them against the vendor and selected nothing from them."
)
_HOOK_ANSWERED = {
    "OK": (
        "OK: the extension answered the pre hook that this tool call could proceed. That "
        "is an answer to the platform, not a report that the tool ran."
    ),
    "CHECK_FAILED": (
        "CHECK_FAILED: the extension refused this tool call. What the platform did with "
        "that answer is the platform's own; a control point configured to fail open runs "
        "the tool anyway."
    ),
    "RATE_LIMIT_EXCEEDED": (
        "RATE_LIMIT_EXCEEDED: the extension refused this tool call for capacity. What the "
        "platform did with that answer is the platform's own."
    ),
}
_HOOK_UNANSWERED = (
    "Nothing recorded. The hook opened this row and no answer was written back to it, "
    "which is the shape an abandoned decision and a crash between the two writes leave."
)
_REPORTED_SUCCESS = (
    "Success, as the platform states it: its own authenticated word, with nothing "
    "ExecBound could check behind it."
)
_REPORTED_FAILURE = (
    "Failure, as the platform states it: its own authenticated word, with nothing "
    "ExecBound could check behind it."
)
_REPORTED_SILENT = (
    "Nothing stated. Either no post hook arrived for this tool call or one arrived "
    "stating no result; both leave this record whatever uncertainty it already had."
)
_NO_END_USER = "None reported."


@dataclass(frozen=True)
class CheckpointLabel:
    """What a human page says about an externally executed operation, as inert text.

    A field is a finished sentence where it is present, built from the row's own state,
    the grant stamp, the claim the tenant retains, this deployment's precondition
    configuration and the transition history this record retains, so the templates print
    strings and decide nothing. The last three are absent where they have nothing to say.
    A label is never authority: it confers no act and settles nothing.
    """

    notice: str
    grant: str
    report_window: str
    precondition: str
    tier: str
    claim: str
    guidance: str | None
    effect: str | None
    correction: str | None


@dataclass(frozen=True)
class CarrierLabel:
    """What one control point said about one record, as inert text.

    ``notice``, ``answered`` and ``reported`` are finished sentences built from this
    deployment's own vocabulary, and ``user`` is one where the platform named none.
    ``control_point``, ``tool``, ``code``, ``error`` and ``metadata`` are the platform's
    own strings, retained verbatim by ``arcade.store`` and shown verbatim here, because an
    operator reading Arcade's log beside this page needs the string Arcade holds rather
    than one ExecBound rewrote. Those are untrusted data: the autoescaping templates are
    what makes them text, and no control on either page is built from any of them.

    The report secret is the credential the correlation row holds at rest, and it is not
    read here: ``CARRIER_QUERY`` selects no column carrying it.
    """

    notice: str
    control_point: str
    tool: str
    user: str
    answered: str
    reported: str
    code: str | None
    error: str | None
    metadata: str | None


def _grant_sentence(state: str, granted: bool, unsettled: bool) -> str:
    """What this record's grant is, paired with the stamp that says whether it has one."""
    if not granted:
        return _NOT_ISSUED_TEXT.get(state, _NO_GRANT_TEXT)
    if state == "DISPATCH_COMMITTED":
        return _GRANT_OUTSTANDING
    return _GRANT_UNSETTLED if unsettled else _GRANT_SETTLED


def _report_sentence(row: Mapping[str, Any], granted: bool, unsettled: bool, now: datetime) -> str:
    """What the report window is for this record, or that it is not a deadline at all."""
    if not granted:
        return _REPORT_UNUSED
    if not unsettled:
        return _REPORT_SETTLED
    closes = row["report_expires_at"]
    template = _REPORT_OPEN if now < closes else _REPORT_CLOSED
    return template.format(closes.isoformat())


def _statement(payload: Mapping[str, Any] | None) -> str:
    """What a transition into the reported-failure state retained, as one clause.

    ``outcomes._settle`` writes the whole ``AssertedOutcome`` under ``asserted`` beside
    ``tier: ASSERTED`` for a settlement an executor's bare word produced. It is read
    defensively rather than assumed: ``store.transition`` takes a plain ``str`` and a
    payload of any shape, so a transition into that state written by something other than
    a report carries no statement, and a page that printed ``None`` for each field would
    be inventing one.
    """
    asserted = payload.get("asserted") if isinstance(payload, Mapping) else None
    if not isinstance(asserted, Mapping):
        return _STATEMENT_ABSENT
    spoken = tuple(asserted.get(name) for name in ("outcome", "reason", "reported_at"))
    if any(value is None for value in spoken):
        return _STATEMENT_ABSENT
    return _STATEMENT.format(*spoken)


def checkpoint_label(
    row: Mapping[str, Any],
    preconditions: PreconditionConfig,
    claims: Mapping[UUID, datetime | None],
    statements: Mapping[UUID, Mapping[str, Any]],
    *,
    now: datetime,
    administrator: bool,
) -> CheckpointLabel:
    """Label one externally executed record; every claim is paired with a state or read.

    The precondition class is a property of an issued grant rather than of the record, and
    the source read here is this deployment's configuration for the provider binding the
    frozen plan names, as it stands now. That is the right source for a record no grant has
    been issued for — the pending approval an approver weighs it on, and the refusal — and
    is not what an issued grant carries. That is retained by the audit chain and, for a
    grant this version issued, recorded on the execution for the outcome route; this label
    reads neither, so a record that was issued a grant is described by no class.

    The canonical claim is read rather than inferred from the state, because what a page
    says a tenant is still holding has to be what it holds. ``statements`` is read for the
    same reason: a corrected record's own ``result`` column holds the correcting evidence
    alone, so the statement the correction replaced is taken from the transition history
    this record retains and from nothing on the record itself.
    """
    frozen = row["frozen_model"]
    state = row["state"]
    granted = row["dispatch_attempted_at"] is not None
    # UNSETTLED is DISPATCH_COMMITTED and INDETERMINATE: a grant something may still
    # settle. It is not "nothing further is coming for this record", which is false of a
    # pending approval, and it is read here for exactly what it does say — that a tier and
    # a settlement guidance sentence about a settled row do not belong on an open one.
    unsettled = state in UNSETTLED
    tier = row["settlement_tier"]
    claimed = row["execution_id"] in claims
    released = claims.get(row["execution_id"])
    guidance = None
    if not unsettled and tier == "ASSERTED" and claimed and released is None:
        stamped = row["dispatch_attempted_at"]
        # Which of the two sentences an administrator is shown is the predicate the kernel
        # decides the correction on, read here rather than restated, so the page and
        # `reconciliation._unsettled_grant_only` cannot drift apart by a fact.
        control = _CORRECTION_CONTROL if _correctable(dict(row)) else _NO_SETTLEMENT_CONTROL
        guidance = (
            _ASSERTION_HOLDS
            + (control if administrator else "")
            + (
                _SWEEP_WAITS
                if stamped is None
                else _SWEEP_RELEASES.format((stamped + ACT_WINDOW).isoformat())
            )
        )
    # A record this deployment has moved out of the reported-failure state was corrected:
    # the edges into that state come from unsettled rows alone, and its two edges out lead
    # to states that are keys of no transition set. So a retained transition into it, on a
    # record no longer in it, is the correction — read from the history rather than decided
    # from the current state name, which the correction replaces.
    stated = statements.get(row["execution_id"])
    return CheckpointLabel(
        notice=EXTERNALLY_EXECUTED,
        grant=_grant_sentence(state, granted, unsettled),
        report_window=_report_sentence(row, granted, unsettled, now),
        precondition=_PRECONDITION_TEXT[
            preconditions.declared(frozen.intent.provider, frozen.intent.provider_operation)
        ]
        if not granted and state in _CLASS_STATES
        else _PRECONDITION_RETAINED,
        tier=_TIER_TEXT.get(tier)
        or ("None yet: nothing has settled this record." if unsettled else "None recorded."),
        claim=(_CLAIM_HELD if released is None else "Released " + released.isoformat() + ".")
        if claimed
        else _NO_CLAIM,
        guidance=guidance,
        effect=_EFFECT_UNKNOWN if state == REPORTED_FAILURE_STATE else None,
        correction=None
        if stated is None or state == REPORTED_FAILURE_STATE
        else _CORRECTION.format(_statement(stated)),
    )


def label_checkpoints(
    conn: Connection,
    tenant: UUID,
    rows: list[dict[str, Any]],
    preconditions: PreconditionConfig,
    *,
    now: datetime,
    administrator: bool,
) -> None:
    """Attach an externally executed label to every row that carries a report window.

    The window is the marker: admission writes it for an operation admitted under a
    mapping the active bundle declared externally executed, which excludes an observing
    tenant, whose request takes the observe branch and is granted nothing — which is what
    leaves an observed row unlabelled. The runtime holds no UPDATE privilege on the
    column, so no runtime statement can give one to an operation ExecBound dispatched. It
    is written before the decision, which is why ``checkpoint_label`` pairs it with the
    row's own state and grant stamp rather than reading it as a live grant. The claims and
    the retained statements are each read in one statement for the page rather than one
    per row.
    """
    for row in rows:
        row["checkpoint"] = None
        # Only a record ExecBound dispatched itself. An externally executed one is acted on
        # by somebody else and its gate label carries the class already — and a grant stamps
        # `dispatch_attempted_at` too, and records the class it was issued under beside it,
        # so reading those columns would describe an attempt ExecBound never made.
        row["precondition"] = (
            None if row["report_expires_at"] is not None else dispatched_precondition(row)
        )
    marked = [row for row in rows if row["report_expires_at"] is not None]
    if not marked:
        return
    claims = {
        found["execution_id"]: found["released_at"]
        for found in conn.execute(
            text(
                "SELECT execution_id, released_at FROM execbound.resource_claims "
                "WHERE tenant_id=:t AND execution_id = ANY(CAST(:ids AS uuid[]))"
            ),
            {"t": tenant, "ids": [row["execution_id"] for row in marked]},
        ).mappings()
    }
    # The statement a correction replaced, read from this record's own transitions. It is
    # ordered oldest first and the last row for an execution is the one kept, so a page
    # shows the most recent statement the history holds rather than whichever row the
    # comprehension happened to see last.
    statements = {
        found["execution_id"]: found["payload"]
        for found in conn.execute(
            text(
                "SELECT execution_id, payload FROM execbound.execution_events "
                "WHERE tenant_id=:t AND execution_id = ANY(CAST(:ids AS uuid[])) "
                "AND to_state=:state ORDER BY created_at, event_id"
            ),
            {
                "t": tenant,
                "ids": [row["execution_id"] for row in marked],
                "state": REPORTED_FAILURE_STATE,
            },
        ).mappings()
    }
    for row in marked:
        row["checkpoint"] = checkpoint_label(
            row, preconditions, claims, statements, now=now, administrator=administrator
        )


# What a page reads off a correlation row, and what it deliberately does not: the report
# secret is the credential `arcade_hooks` holds at rest, and this statement selects no
# column carrying it. The order is the order the hooks arrived in, so a record adopted by
# a second Arcade execution id reads oldest first.
CARRIER_QUERY = text("""
    SELECT execution_id, arcade_execution_id, toolkit, tool_name, tool_version,
           reported_user_id, decision, reported_success, reported_code, reported_error,
           reported_metadata
    FROM execbound.arcade_hooks
    WHERE tenant_id=:t AND execution_id = ANY(CAST(:ids AS uuid[]))
    ORDER BY created_at, arcade_execution_id
""")


def carrier_label(hook: Mapping[str, Any]) -> CarrierLabel:
    """One correlation row as inert text; a display object no decision is given.

    The tool identity is joined into one string for a reader. Its three parts arrive
    through ``arcade.models.ToolInfo``, whose patterns admit no space and none of
    ``< > & " '``, so the join is unambiguous for a row the hook route wrote; the column
    checks are lengths alone, so this says what the join is rather than what the database
    guarantees, and the template escapes the result either way.

    ``reported_metadata`` is a free object — the map's ``expect`` comparison is the whole
    of what reads it — so it is serialized here with its keys sorted and shown whole.
    Both its keys and its values are the platform's, and both reach the page as text.
    """
    metadata = hook["reported_metadata"]
    return CarrierLabel(
        notice=CONTROL_POINT_CARRIED,
        control_point=hook["arcade_execution_id"],
        tool=f"{hook['toolkit']}.{hook['tool_name']} {hook['tool_version']}",
        user=hook["reported_user_id"] or _NO_END_USER,
        # The column admits the three hook codes and null, so the fallback below is the
        # null case: a row the extension opened and wrote no answer back to.
        answered=_HOOK_ANSWERED.get(hook["decision"] or "", _HOOK_UNANSWERED),
        reported=_REPORTED_SILENT
        if hook["reported_success"] is None
        else (_REPORTED_SUCCESS if hook["reported_success"] else _REPORTED_FAILURE),
        code=hook["reported_code"],
        error=hook["reported_error"],
        metadata=None if metadata is None else json.dumps(metadata, sort_keys=True),
    )


def label_carriers(conn: Connection, tenant: UUID, rows: list[dict[str, Any]]) -> None:
    """Attach what a control point said about each record, read in one statement.

    A record can be named by more than one correlation row: admission adopts a second
    Arcade execution id onto a granted intent and the refusal is retained beside the grant
    it was refused against, so this attaches a tuple and the templates iterate it. A record
    no hook opened gets an empty tuple rather than nothing at all, because the Jinja
    environment is ``StrictUndefined`` and a missing key raises at render.

    What is attached here is display data rather than authority: the templates print it
    and no decision is handed it. The tool identity, the end user, the reported strings
    and the reported metadata are the platform's own statements about itself, which the
    tool map weighs before a decision and which this shows afterwards so an operator can
    read Arcade's log beside ExecBound's.
    """
    for row in rows:
        row["carriers"] = ()
    if not rows:
        return
    found: dict[UUID, list[CarrierLabel]] = {}
    for hook in conn.execute(
        CARRIER_QUERY, {"t": tenant, "ids": [row["execution_id"] for row in rows]}
    ).mappings():
        found.setdefault(hook["execution_id"], []).append(carrier_label(dict(hook)))
    for row in rows:
        row["carriers"] = tuple(found.get(row["execution_id"], ()))


ACTIVITY_QUERY = frozenset({"state", "action", "principal", "since_hours", "cursor"})
ACTIVITY_STATES = (
    "UNCERTAIN",
    "PENDING_APPROVAL",
    "DISPATCH_COMMITTED",
    "INDETERMINATE",
    "EXECUTED",
    "FAILED_NOT_EXECUTED",
    # A settled state the filter has to name, or the activity console could show the row and
    # could not ask for it. `ATTEMPTED` and `RESERVED` are absent too and stay absent: they
    # are transient, and a filter offering one would answer with whatever happened to be
    # mid-flight when the page was built.
    REPORTED_FAILURE_STATE,
    "DENIED",
    "STALE_AUTHORIZATION",
    "OBSERVED",
)
SINCE_HOURS = (1, 24, 168, 720)
PAGE_SIZE = 50


def encode_cursor(created_at: datetime, execution_id: UUID) -> str:
    """An opaque page position; it only bounds a read inside the reader's own scope."""
    raw = f"{created_at.astimezone(UTC).isoformat()}|{execution_id}".encode()
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_cursor(value: str) -> tuple[datetime, UUID]:
    padded = value + "=" * (-len(value) % 4)
    raw = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
    stamp, separator, identifier = raw.partition("|")
    if not separator:
        raise ValueError("Malformed cursor")
    created_at = datetime.fromisoformat(stamp)
    if created_at.tzinfo is None:
        raise ValueError("Naive cursor time")
    return created_at, UUID(identifier)


def activity_filters(request: Request, now: datetime) -> dict[str, Any]:
    """Validate the activity list's query strictly; anything unexpected is a 400."""
    values = dict(request.query_params.multi_items())
    filters: dict[str, Any] = {
        "state": None,
        "action": None,
        "principal": None,
        "since_hours": None,
        "since": None,
        "cursor": None,
    }
    try:
        if values.get("state"):
            if values["state"] not in ACTIVITY_STATES:
                raise ValueError("Unknown state")
            filters["state"] = values["state"]
        if values.get("action"):
            if values["action"] not in PRODUCTION_ACTIONS.names:
                raise ValueError("Unknown action")
            filters["action"] = values["action"]
        if values.get("principal"):
            principal = UUID(values["principal"])
            if str(principal) != values["principal"]:
                raise ValueError("Malformed principal")
            filters["principal"] = principal
        if values.get("since_hours"):
            hours = int(values["since_hours"])
            if hours not in SINCE_HOURS:
                raise ValueError("Unsupported window")
            filters["since_hours"] = hours
            filters["since"] = now - timedelta(hours=hours)
        if values.get("cursor"):
            if len(values["cursor"]) > 200:
                raise ValueError("Cursor too long")
            filters["cursor"] = decode_cursor(values["cursor"])
    except (ValueError, TypeError, UnicodeDecodeError):
        raise HTTPException(400, "Invalid request") from None
    return filters


def records(
    runtime: Runtime,
    session: Session,
    *,
    pending: bool = False,
    lapsed: bool = False,
    execution_id: UUID | None = None,
    approval_id: UUID | None = None,
    state: str | None = None,
    action: str | None = None,
    principal: UUID | None = None,
    since: datetime | None = None,
    target: UUID | None = None,
    decided_since: datetime | None = None,
    cursor: tuple[datetime, UUID] | None = None,
    limit: int = PAGE_SIZE,
    enriched: bool = False,
    reviewing: bool = False,
    outcome: str | None = None,
    others: bool = False,
    delivery: bool = False,
) -> list[dict[str, Any]]:
    """Bounded read; SQL scopes first and current authorization is checked again.

    `target` narrows to one canonical target inside the same scope clause. `enriched`
    attaches, after every row has passed its scope check, the transition history of the
    rows returned (`events`, oldest first) and the label of each row's agent
    (`agent_label`), which the console's drawer and list show as words; the pages ask for
    neither, so their reads are unchanged.
    ``decided_since`` keeps the rows whose approval reached its final decision at or after
    that instant, for the console's "decided today" list
    (#333): one more predicate inside
    the same scoped, fenced and bounded read, so the list has exactly the authority the
    Activity page has and no read of its own. ``pending`` is what an approver can still
    decide, so it holds only approvals whose deadline has not passed; ``lapsed`` is the
    other half of the same set, the approvals that ran out of time undecided, which stay
    readable rather than disappearing
    (#426). One clock decides both, the
    runtime's, so the two never overlap and never leave a row in neither. ``lapsed`` holds a
    row on either side of the recovery run's sweep: an approval still `PENDING` or
    `APPROVED` past its deadline, which is what the row reads as between the expiry and the
    next run, and one the sweep has since moved to `EXPIRED`, whose execution is no longer
    `PENDING_APPROVAL`. An approval that ran out of time is a fact somebody should be able
    to read, so ending it never removes it from the one view that says so.
    ``outcome`` keeps the rows of one key of `outcomes.PREDICATES`, the same predicate the
    value report counts with, so a count and the list it opens cannot disagree (#678). The
    caller validates the key; the statement binds it and never formats it.
    ``others`` keeps the rows the reader holds no review assignment for: the negation of the
    reviewer predicate, inside the same scoped, fenced and bounded read, for an administrator's
    "Waiting on others" (#678). Only an administrator reading outside their own review scope
    may ask for it; any other reader is refused here, not only by the route.
    ``delivery`` attaches `delivery_times()` beside the announcement counts as
    `delivery_times`, under the same scope check; only the approvals pages ask, so the record
    pages, Home and the board read one statement fewer per row.
    """
    identity = session.identity
    with runtime.db.transaction(identity.tenant_id) as conn:
        if identity.kind not in {"HUMAN_APPROVER", "ADMIN"}:
            raise ExecutionError("INVALID_IDENTITY")
        if others and (identity.kind != "ADMIN" or reviewing):
            raise ExecutionError("INVALID_IDENTITY")
        store.identity_check(conn, identity, runtime.clock, identity.kind)
        store.fence(conn, identity.tenant_id, runtime.clock)
        check_session(conn, session, runtime.clock)
        from execbound.access_control import review_read_spaces, review_scoped

        scoped = reviewing or review_scoped(conn, identity)
        read_spaces = set() if reviewing else set(review_read_spaces(conn, identity))
        # The visible set, computed inside the fence beside the identity and session
        # rechecks. `records()` is the one read behind Activity, Home, the approval queue,
        # the board and the drawer, so every one of them inherits the space filter from
        # here; the predicate comes from `space_clause` and is never built by hand.
        visibility = visible_spaces(conn, session)
        # A list is filtered by the space the person is looking at; a single record named
        # by its own identifier is authorised by membership and answered whatever the
        # session holds, which is what lets an approval link open in the space that owns it.
        # `whole()` drops only the current space, never the bound: a record in a space this
        # person does not belong to is unreachable either way.
        named = execution_id is not None or approval_id is not None
        space = space_clause(visibility.whole() if named else visibility, "e")
        rows = (
            conn.execute(
                text(
                    """
            SELECT e.* FROM execbound.executions e WHERE e.tenant_id=:t
            AND (CAST(:e AS uuid) IS NULL OR e.execution_id=:e)
            AND (CAST(:ap AS uuid) IS NULL OR EXISTS (
                SELECT 1 FROM execbound.approvals a WHERE a.tenant_id=e.tenant_id
                AND a.execution_id=e.execution_id AND a.approval_id=:ap))
            AND (NOT :pending OR (e.state='PENDING_APPROVAL' AND EXISTS (
                SELECT 1 FROM execbound.approvals a WHERE a.tenant_id=e.tenant_id
                AND a.execution_id=e.execution_id AND a.state='PENDING'
                AND a.expires_at > :now)))
            AND (NOT :lapsed OR EXISTS (
                SELECT 1 FROM execbound.approvals a WHERE a.tenant_id=e.tenant_id
                AND a.execution_id=e.execution_id AND (a.state='EXPIRED' OR
                (a.state IN ('PENDING','APPROVED') AND a.expires_at <= :now
                 AND e.state='PENDING_APPROVAL'))))
            AND (NOT :scoped OR e.space_id=ANY(CAST(:read_spaces AS uuid[])) OR EXISTS (
                SELECT 1 FROM execbound.effective_approval_scopes s
                WHERE s.tenant_id=e.tenant_id AND s.approver_id=:p AND s.active
                AND s.canonical_target_id=e.canonical_target_id
                AND s.space_id=e.space_id
                AND s.action=e.frozen -> 'intent' ->> 'action'))
            AND (NOT :others OR NOT EXISTS (
                SELECT 1 FROM execbound.effective_approval_scopes s
                WHERE s.tenant_id=e.tenant_id AND s.approver_id=:p AND s.active
                AND s.canonical_target_id=e.canonical_target_id
                AND s.space_id=e.space_id
                AND s.action=e.frozen -> 'intent' ->> 'action'))
            AND (CAST(:state AS text) IS NULL OR e.state=:state OR (:state='UNCERTAIN'
                AND e.state IN ('DISPATCH_COMMITTED', 'INDETERMINATE')))
            AND (CAST(:action AS text) IS NULL OR e.frozen -> 'intent' ->> 'action' = :action)
            AND (CAST(:principal AS uuid) IS NULL OR e.principal_id=:principal)
            AND (CAST(:target AS uuid) IS NULL OR e.canonical_target_id=:target)
            AND (CAST(:since AS timestamptz) IS NULL OR e.created_at > :since)
            AND (CAST(:decided_since AS timestamptz) IS NULL OR EXISTS (
                SELECT 1 FROM execbound.approvals a WHERE a.tenant_id=e.tenant_id
                AND a.execution_id=e.execution_id AND a.decided_at >= :decided_since))
            AND (CAST(:cursor_at AS timestamptz) IS NULL OR (e.created_at, e.execution_id)
                < (CAST(:cursor_at AS timestamptz), CAST(:cursor_id AS uuid)))"""
                    # The outcome predicates, module literals assembled once at import; the
                    # key is bound, so with none the guard folds away.
                    + outcomes.OUTCOME_FILTER  # nosec B608 - module literals only
                    # One `AND`, from the one helper, appended to the one statement.
                    + space.sql  # nosec B608 - a literal from space_clause; values are bound
                    + """
            ORDER BY e.created_at DESC,e.execution_id DESC LIMIT :limit
        """
                ),
                {
                    **space.params,
                    "t": identity.tenant_id,
                    "p": identity.principal_id,
                    "scoped": scoped,
                    "read_spaces": list(read_spaces),
                    "pending": pending,
                    "lapsed": lapsed,
                    "others": others,
                    "now": store.now(runtime.clock),
                    "e": execution_id,
                    "ap": approval_id,
                    "state": state,
                    "action": action,
                    "principal": principal,
                    "target": target,
                    "since": since,
                    "decided_since": decided_since,
                    "outcome": outcome,
                    "cursor_at": cursor[0] if cursor else None,
                    "cursor_id": cursor[1] if cursor else None,
                    "limit": min(max(int(limit), 1), PAGE_SIZE + 1),
                },
            )
            .mappings()
            .all()
        )
        # Group names are read once per call so the record page can label group scopes;
        # they are tenant data shown as inert text, never a lookup the agent controls.
        names = {
            found.group_id: found.name
            for found in conn.execute(
                text("SELECT group_id, name FROM execbound.principal_groups WHERE tenant_id=:t"),
                {"t": identity.tenant_id},
            )
        }
        # Sample targets (#420): the accounts the install function marked, read once, so every
        # row a sample account served carries the mark the console shows as a badge.
        from execbound.samples import sample_accounts

        marked = sample_accounts(conn, identity.tenant_id)
        result = []
        for value in rows:
            row = dict(value)
            row_scoped = scoped and row["space_id"] not in read_spaces
            if row_scoped:
                store.scope_check(conn, identity, row, runtime.clock)
            row["frozen_model"] = store.frozen(row)
            row["approval"] = store.approval_row(conn, row)
            row["decisions"] = (
                store.approval_decisions(conn, identity.tenant_id, row["approval"]["approval_id"])
                if row["approval"]
                else []
            )
            row["notifications"] = (
                notification_summary(conn, identity.tenant_id, row["approval"]["approval_id"])
                if row["approval"]
                else None
            )
            if delivery and row["approval"]:
                # When the announcements were queued and last delivered, for the approvals
                # pages alone (#678): every other reader skips the statement.
                row["delivery_times"] = delivery_times(
                    conn, identity.tenant_id, row["approval"]["approval_id"]
                )
            row["bundle"] = store.bundle(conn, identity.tenant_id, row["bundle_id"])
            frozen = row["frozen_model"]
            row["sample"] = frozen.intent.account_id in marked
            row["request_ref"] = f"EB-{row['request_number']}"
            row["external_case"] = frozen.request.external_case
            if named:
                from execbound.surfaces.request_context import attach_context

                attach_context(
                    conn,
                    row,
                    principal=identity.principal_id,
                    scoped=scoped,
                    read_spaces=read_spaces,
                    space_sql=space.sql,
                    space_params=space.params,
                )
            row["action_label"] = action_label(frozen, runtime.catalog)
            row["arguments"] = tuple(sorted(frozen.intent.arguments.root.items()))
            row["resource_class"] = resource_class(frozen, runtime.catalog)
            row["environment"] = environment_label(frozen)
            row["applicable_limits"] = tuple(
                {
                    "rule": rule,
                    "scope": limit_label(rule, names),
                    "actions": ", ".join(rule.action_names),
                }
                for rule in row["bundle"].limits
                if frozen.intent.action in rule.action_names
            )
            result.append(row)
        # Built after the loop, so an approver session's per-row scope check has already
        # run for every row a label is attached to. The reader's kind reaches the label
        # because one sentence of it is about a control only an administrator is offered.
        label_checkpoints(
            conn,
            identity.tenant_id,
            result,
            runtime.preconditions,
            now=runtime.clock.now(),
            administrator=identity.kind == "ADMIN",
        )
        # Beside it for the same reason: after the loop, so an approver session's per-row
        # scope check has already run for every row a control point's strings are attached
        # to. This deployment need not serve the hooks for a record to have been carried by
        # them, so the read is of the correlation table and not of any configuration.
        label_carriers(conn, identity.tenant_id, result)
        if enriched and result:
            # After the loop for the same reason as the labels above: every row an event or
            # a label is attached to has already passed an approver session's scope check.
            # One query each; the ids are the rows' own, never a caller's list.
            ids = [row["execution_id"] for row in result]
            history: dict[UUID, list[dict[str, Any]]] = {row["execution_id"]: [] for row in result}
            for found in conn.execute(
                text(
                    "SELECT execution_id, event_id, actor_id, from_state, to_state, "
                    "created_at, payload FROM execbound.execution_events "
                    "WHERE tenant_id=:t AND execution_id = ANY(CAST(:ids AS uuid[])) "
                    "ORDER BY created_at, event_id"
                ),
                {"t": identity.tenant_id, "ids": ids},
            ).mappings():
                history[found["execution_id"]].append(dict(found))
            people = {row["principal_id"] for row in result}
            people.update(event["actor_id"] for events in history.values() for event in events)
            people.update(decided["principal_id"] for row in result for decided in row["decisions"])
            # Each principal's kind, label and counting number, so a page names an agent or
            # a person one way: its label, else "Agent 3" or "User 3" (#678).
            principals = principal_facts(conn, identity.tenant_id, people)
            for row in result:
                row["events"] = history[row["execution_id"]]
                row["principals"] = principals
        store.identity_check(conn, identity, runtime.clock, identity.kind)
        check_session(conn, session, runtime.clock)
        return result


def settle_grant(
    runtime: Runtime,
    session: Session,
    row: dict[str, Any],
    reason: str,
    record: bytes,
    authority_check: AuthorityCheck,
) -> ExecutionView:
    """Settle one granted checkpoint from its own evidence; no connector.

    The evidence is an executor's signed record, an ES256 attestation, or the provider's
    journal of the exact command, and it settles at the tier the verifier reports for it:
    ATTESTED for the first two and PROVIDER_VERIFIED for the journal.

    The administrator exit for an unreported grant. No connector is looked up: admission
    refuses a Gate mapping whose account already has one, and a connector configured
    afterwards knows nothing about what the executor did. This goes instead to the
    connector-free ``reconcile`` with the runtime's checkpoint verifier, which checks the
    tenant's registered executor keys and the journal key the deployment configured for the
    grant's Gate account, if any. That is also what lets ``reconcile`` settle at all, since
    it refuses a grant to any verifier that does not attest an external execution. This
    control carries the two settlements ``reconcile`` admits for a grant, and the row
    decides which one it is rather than the page: the exit from retained uncertainty for a
    row in ``UNSETTLED``, and the correction for a ``_correctable`` row met by a verified
    non-execution. Those are the two cases ``_unsettled_grant_only`` leaves standing; a
    settled grant outside them is refused ``INVALID_STATE``. The page offers the control for
    either kind of row, and it is ``reconcile`` and ``_correctable`` that decide what is
    admissible. The continuation binds the record and not the state that record was read in,
    so a grant a report settles between the render and the submission arrives here settled
    and is corrected if the record supplied verifies as a non-execution — the case where the
    rendered page and the row disagree, which needs no state on the token because the row is
    read again under the fence.

    The key ring is read twice. Here, on its own connection, so a ring that will not load
    is named as such before ``reconcile`` opens anything; and again inside ``reconcile``'s
    fenced transaction, which is the read the settlement rests on. The grant instant is
    ``dispatch_attempted_at`` and is stamped once, so a registration or a retirement
    landing between the two reads cannot change which keys speak for this grant — but a
    compromise is retroactive whatever that instant, and one committing in that window
    would otherwise settle the grant on a stolen key's record.
    """
    with runtime.db.transaction(session.identity.tenant_id) as conn:
        store.identity_check(conn, session.identity, runtime.clock, "ADMIN")
        check_session(conn, session, runtime.clock)
        try:
            verifier = runtime.verifier_for(conn, row)
        except ValueError:
            # A tenant whose key ring is empty or holds a row no current guard would
            # accept has no attested reporting at all. It fails closed, and the code says
            # which ring to look at rather than the generic 503 a caller retries: nothing
            # about this answer changes until an administrator lists the tenant's executor
            # keys and replaces the row that will not load.
            raise ExecutionError("INVALID_KEY_RING") from None
    return reconcile(
        runtime.db,
        session.identity,
        row["execution_id"],
        reason=reason,
        evidence=record,
        verifier=verifier,
        verifier_for=runtime.verifier_for,
        clock=runtime.clock,
        authority_check=authority_check,
    )


# How each coverage class the collector's reconciliation assigns is named on the page, so
# the Inventory page shows exactly the classification the instrumentation-gap rule saw.
COVERAGE_LABELS = {
    "instrumented": "Instrumented",
    "registered_stale": "Registered, not reporting",
    "discovered_only": "Outbound actions, no reporting source",
    "no_outbound": "No outbound actions",
    "coverage_unknown": "Coverage unknown",
    "disabled": "Disabled in the platform",
    None: "Not reconciled yet",
}


def tenant_mode(runtime: Runtime, session: Session) -> str:
    """The tenant's enforcement mode for the notice; admission reads it inside the fence."""
    identity = session.identity
    with runtime.db.transaction(identity.tenant_id) as conn:
        store.identity_check(conn, identity, runtime.clock, identity.kind)
        check_session(conn, session, runtime.clock)
        return store.enforcement_mode(conn, identity.tenant_id)


def active_stop(runtime: Runtime, session: Session) -> StopState | None:
    """The tenant's emergency stop for the banner; the decision routes recheck it themselves."""
    identity = session.identity
    with runtime.db.transaction(identity.tenant_id) as conn:
        store.identity_check(conn, identity, runtime.clock, identity.kind)
        check_session(conn, session, runtime.clock)
        return store.stop(conn, identity.tenant_id)


def signal_sources(row: Mapping[str, Any]) -> set[UUID]:
    """The sources of a row's signal facts, whose labels the page names."""
    return {fact.source_id for fact in row["frozen_model"].facts if fact.source_kind == "signal"}


def signal_source_labels(runtime: Runtime, session: Session, ids: set[UUID]) -> dict[UUID, str]:
    """The labels of some of the tenant's signal sources this person's spaces may use.

    Read inside the fence, through the shared space predicate: a source a space of this
    person's owns, or one offered tenant-wide. A source of another space is left out, so a
    row this person may see whose frozen plan names one carries no label for it, and the
    pages name the fact by its kind instead; nothing of that source reaches them. The
    identifiers come from one record named by its own identifier, so the set is read as
    `records()` reads that record, whatever space the session is looking at
    (`Visibility.whole`).

    It names its columns: the runtime role cannot read a source's token digests.
    """
    if not ids:
        return {}
    identity = session.identity
    with runtime.db.transaction(identity.tenant_id) as conn:
        store.identity_check(conn, identity, runtime.clock, identity.kind)
        check_session(conn, session, runtime.clock)
        # One `AND`, from the one helper, appended to the one statement.
        space = space_clause(visible_spaces(conn, session).whole(), "s", offered=True)
        found = conn.execute(
            text(
                "SELECT s.source_id, s.label FROM execbound.signal_sources s "
                "WHERE s.tenant_id=:t AND s.source_id = ANY(CAST(:ids AS uuid[]))" + space.sql  # nosec B608 - a literal from space_clause; values are bound
            ),
            {**space.params, "t": identity.tenant_id, "ids": sorted(str(item) for item in ids)},
        )
        return {row.source_id: str(row.label) for row in found}


def _nonce(session: Session, csrf: str) -> str:
    return hashlib.sha256((str(session.session_id) + ":" + csrf).encode()).hexdigest()


def authority_guard(runtime: Runtime, session: Session) -> AuthorityCheck:
    """Recheck the session inside the kernel's own transaction; a lapsed one fails closed.

    The pages and the console API hand this to `decide_approval`, `reconcile` and their
    kin, so a session that ended between the request and the fenced write is refused as
    `INVALID_IDENTITY` by the kernel rather than tolerated by the page.
    """

    def check(conn: Any) -> None:
        try:
            check_session(conn, session, runtime.clock)
        except SessionError:
            raise ExecutionError("INVALID_IDENTITY") from None

    return check


def _form_state(
    config: HumanConfig,
    session: Session,
    csrf: str,
    row: dict[str, Any],
    audience: Audience,
    runtime: Runtime,
) -> str:
    approval = row["approval"]
    if audience == "approval.decide" and approval:
        # A reviewer reads before deciding: the form lives as long as the session and
        # the approval do, and the session renews while they read.
        expiry = min(session.expires_at, approval["expires_at"])
    else:
        expiry = min(session.expires_at, runtime.clock.now() + timedelta(minutes=2))
    return sign(
        Continuation(
            tenant_id=session.identity.tenant_id,
            principal_id=session.identity.principal_id,
            credential_id=session.identity.credential_id,
            audience=audience,
            execution_id=row["execution_id"],
            approval_id=approval["approval_id"] if approval else None,
            plan_hash=row["plan_hash"],
            expires_at=expiry,
            nonce=_nonce(session, csrf),
        ),
        config.keys,
    )


def continuation_row(
    runtime: Runtime,
    config: HumanConfig,
    session: Session,
    csrf: str,
    state: str,
    audience: Audience,
) -> dict[str, Any]:
    """The record a continuation binds, re-read under the fence, or `InvalidContinuation`.

    The token is verified for this session's tenant, principal, credential and audience;
    its nonce must be this session's; the record it names is read again through `records`
    (so an approver's scope applies to it now, not when the page was built) and must still
    carry the plan hash and the approval the token was signed over. The pages' forms and
    the console API's mutations both bind through here, so one check decides for both.
    """
    claim = verify(
        state,
        config.keys,
        tenant_id=session.identity.tenant_id,
        principal_id=session.identity.principal_id,
        credential_id=session.identity.credential_id,
        audience=audience,
        now=runtime.clock.now(),
    )
    if not hmac.compare_digest(claim.nonce, _nonce(session, csrf)):
        raise InvalidContinuation
    rows = records(
        runtime, session, execution_id=claim.execution_id, reviewing=audience == "approval.decide"
    )
    if not rows or rows[0]["plan_hash"] != claim.plan_hash:
        raise InvalidContinuation
    row = rows[0]
    approval = row["approval"]
    if claim.approval_id != (approval["approval_id"] if approval else None):
        raise InvalidContinuation
    return row


_templates = Environment(
    loader=PackageLoader("execbound.surfaces", "templates"),
    autoescape=True,
    undefined=StrictUndefined,
)


def deadline_clock(row: dict[str, Any]) -> str | None:
    """Which clock set the approval's expiry: the tenant's deadline or the plan's context.

    Off makes the two equal, and the plan's validity is the one that binds either way.
    """
    approval = row.get("approval")
    if not approval:
        return None
    valid_until = row["frozen_model"].valid_until
    return "context validity" if approval["expires_at"] >= valid_until else "approval deadline"


def _page(template: str, *, service: ServiceLinks, **data: Any) -> HTMLResponse:
    """A page from its template. `service` is required: `base.html`'s footer reads it, so a
    page cannot be rendered without saying which of the deployment's links it shows."""
    return HTMLResponse(_templates.get_template(template).render(service=service, **data))


def login_page(
    config: HumanConfig,
    csrf: str,
    *,
    runtime: Runtime,
    problem: str | None = None,
    status: int = 200,
    directory: Any = None,
    setup: bool = False,
) -> HTMLResponse:
    """`/login`, however it was reached: the page itself and every refusal that lands back on it.

    One definition for the three routers that render it, so a method added later cannot show a
    different set of buttons or set the CSRF cookie with a different rule, or leave out a
    loaded plugin's sign-in link or recovery link. Both are asked for here, on each render,
    because the plugins are loaded after `HumanConfig` is built and so cannot travel on them.
    """
    page = _page(
        "login.html",
        service=config.service,
        title="Sign in",
        session=None,
        csrf=csrf,
        providers=config.providers,
        setup=setup,
        directory=directory,
        problem=problem,
        sign_in_link=runtime.plugins.shown_sign_in_link(runtime),
        recovery_link=runtime.plugins.shown_recovery_link(runtime),
    )
    page.status_code = status
    page.set_cookie(
        config.cookie("login"),
        csrf,
        max_age=300,
        httponly=True,
        secure=config.secure,
        samesite="strict",
        path="/",
    )
    return page


def directory_hint(runtime: Runtime, config: HumanConfig, cookies: Mapping[str, str]) -> Any:
    """The tenant button `/login` offers this browser, or None.

    The form takes an address and no tenant, and asking which directory an address belongs to
    would tell a stranger which addresses exist and where they work. So the button follows the
    browser instead: a successful sign-in through a tenant's provider leaves a cookie naming it,
    and a browser that has never been through one is told nothing. A read that fails, a cookie
    that names nothing and a provider that is no longer enabled all answer None, because a hint
    that cannot be resolved is not an error anybody should see.
    """
    from execbound import directory_store

    if config.directory is None:
        return None
    value = cookies.get(config.cookie("directory"), "")
    try:
        row = directory_store.locate_provider(runtime.db, UUID(value))
    except (directory_store.DirectoryError, ValueError, AttributeError):
        return None
    if row is None or row.state != "enabled":
        return None
    parsed = urlsplit(row.authorization_endpoint)
    return {
        "provider_id": str(row.provider_id),
        "name": row.name,
        "origin": f"{parsed.scheme}://{parsed.netloc}",
    }


# Status-keyed copy for browser requests; it never carries request or record details.
_ERROR_TEXT: dict[int, tuple[str, str]] = {
    400: ("The request could not be read.", "Go back to the page and try again from there."),
    401: ("Your session has ended.", "Sign in again to continue."),
    403: (
        "This session cannot do that.",
        "Your account needs permission for this action. Contact an administrator.",
    ),
    404: ("Nothing is here.", "The record does not exist or is outside your scope."),
    409: (
        "This has already been decided or has changed.",
        "Return to the list to see the current state.",
    ),
    423: (
        "The emergency stop is active.",
        "Decisions and new actions resume when an administrator releases it.",
    ),
    429: ("Too many attempts.", "Wait a moment before trying again."),
    503: ("The service is unavailable.", "Try again shortly; nothing was changed."),
}


def error_page(
    status: int, headers: Mapping[str, str] | None = None, *, service: ServiceLinks
) -> HTMLResponse:
    """An HTML error for a browser: the same status as the JSON error, generic copy only."""
    title, guidance = _ERROR_TEXT.get(status, ("Something went wrong.", "Try again shortly."))
    body = _templates.get_template("error.html").render(
        title="Error",
        session=None,
        csrf="",
        status=status,
        heading=title,
        guidance=guidance,
        service=service,
    )
    return HTMLResponse(body, status_code=status, headers=dict(headers or {}))


def wants_html(request: Request) -> bool:
    """A browser asking for a page, as opposed to an API or intake client."""
    accept = request.headers.get("accept", "")
    path = request.url.path
    return "text/html" in accept and not path.startswith(("/v1/", "/mcp", "/health/", "/api/"))


def time_left(seconds: int) -> str:
    """Whole minutes and seconds for the approval page; never negative."""
    seconds = max(0, int(seconds))
    minutes, rest = divmod(seconds, 60)
    return f"{minutes} min {rest} s" if minutes else f"{rest} s"


@dataclass(frozen=True)
class RequestGuards:
    """The request boundary, cookie, form and session checks every human page shares."""

    cookies: Callable[[Request], dict[str, str]]
    boundary: Callable[..., Awaitable[None]]
    form: Callable[..., Awaitable[dict[str, str]]]
    session_for: Callable[..., Awaitable[tuple[Session, str]]]
    mutation: Callable[..., Awaitable[tuple[Session, str, dict[str, str]]]]
    # The boundary of a console API request that carries a personal access token.
    token_boundary: Callable[..., Awaitable[None]]


def landing(kind: str) -> str:
    """Where a signed-in person starts: an approver on Approvals, everyone else on Home,
    where the guided setup and the overview are. Fixed by their role; no request chooses it,
    so there is no `next` parameter anywhere and therefore no open redirect."""
    return "/approvals" if kind == "HUMAN_APPROVER" else "/"


def session_response(
    config: HumanConfig, runtime: Runtime, granted: SessionGrant, location: str
) -> RedirectResponse:
    """The cookies every sign-in issues, whatever proved who the person is, and a 303 on.

    One definition of the cookies for the credential exchange, the password form and every
    provider callback, so a method added later cannot quietly issue one with a different
    rule. The 303 is for a sign-in that began on this site; a provider's callback answers
    with `session_landing` instead.
    """
    return _session_cookies(
        RedirectResponse("/mfa" if granted.mfa_required else location, status_code=303),
        config,
        runtime,
        granted,
    )


def onward(location: str, heading: str, service: ServiceLinks) -> HTMLResponse:
    """A page of this site's own that moves the browser on to `location`.

    Every callback a provider or a directory sends the browser to is a cross-site top-level
    navigation, and a request that follows a redirect in a chain a cross-site navigation began is
    sent without a SameSite=Strict cookie. A 303 from a callback therefore reached the next page
    with no session, and that page sent the person back to `/login`. The session cookie stays
    Strict. What changes is where the next request starts: a navigation this page begins, by its
    refresh or by the link a person can press, starts on this site and carries it. `location` is
    a fixed path of this application or a canonical console address from the signed hint.
    """
    return _page(
        "onward.html",
        service=service,
        title=heading.rstrip("."),
        session=None,
        public=True,
        heading=heading,
        location=location,
    )


def session_landing(
    config: HumanConfig, runtime: Runtime, granted: SessionGrant, location: str
) -> HTMLResponse:
    """The session's cookies on the onward page, for a sign-in a provider's callback ends."""
    return _session_cookies(
        onward(
            "/mfa" if granted.mfa_required else location,
            "Verify your identity." if granted.mfa_required else "Signed in.",
            config.service,
        ),
        config,
        runtime,
        granted,
    )


def _session_cookies[R: Response](
    response: R, config: HumanConfig, runtime: Runtime, granted: SessionGrant
) -> R:
    # Personal workspace cookies do not roll on reads: a delayed response from an
    # old workspace must not overwrite a newly selected workspace's cookies. The
    # server still enforces idle expiry on every request.
    cookie_expiry = granted.identity.expires_at if granted.account_bound else granted.expires_at
    ttl = max(0, int((cookie_expiry - runtime.clock.now()).total_seconds()))
    if granted.account_token is not None:
        response.set_cookie(
            config.cookie("account"),
            granted.account_token,
            max_age=int(SIGN_IN_LIFETIME.total_seconds()),
            httponly=True,
            secure=config.secure,
            samesite="strict",
            path="/",
        )
    for name, value in (("session", granted.token), ("csrf", granted.csrf_token)):
        response.set_cookie(
            config.cookie(name),
            value,
            max_age=ttl,
            httponly=True,
            secure=config.secure,
            samesite="strict",
            path="/",
        )
    response.delete_cookie(
        config.cookie("login"), secure=config.secure, httponly=True, samesite="strict"
    )
    if not granted.mfa_required:
        response.delete_cookie(
            config.cookie("review_return"), secure=config.secure, httponly=True, samesite="lax"
        )
    return response


def trust_cookie[R: Response](
    response: R, config: HumanConfig, runtime: Runtime, value: str, expires_at: datetime
) -> R:
    """Set the trusted-browser cookie (#859) for as long as the trust itself lasts.

    Lax, not Strict like the session's: a Google, GitHub, Microsoft or directory sign-in
    finishes on a cross-site navigation, where a Strict cookie is not sent. It grants nothing
    by itself; `GET /mfa` reads it only for a session already past the password or provider."""
    response.set_cookie(
        config.cookie("trust"),
        value,
        max_age=max(0, int((expires_at - runtime.clock.now()).total_seconds())),
        httponly=True,
        secure=config.secure,
        samesite="lax",
        path="/",
    )
    return response


def request_guards(runtime: Runtime, config: HumanConfig) -> RequestGuards:
    """Build the guards once per router; other page modules reuse the same checks."""

    def cookies(request: Request) -> dict[str, str]:
        result: dict[str, str] = {}
        for header in request.headers.getlist("cookie"):
            for part in header.split(";"):
                name, separator, value = part.strip().partition("=")
                if not separator or name in result:
                    raise HTTPException(400, "Invalid request")
                result[name] = value
        return result

    async def _query(request: Request, query: frozenset[str] | None) -> None:
        keys = [key for key, _ in request.query_params.multi_items()]
        if query is not None and keys:
            if not query or set(keys) - query or len(set(keys)) != len(keys):
                raise HTTPException(400, "Invalid request")

    async def _rest(request: Request) -> None:
        if request.method == "GET" and (
            request.headers.get("content-length", "0") != "0"
            or "transfer-encoding" in request.headers
        ):
            raise HTTPException(400, "Invalid request")
        if (
            request.headers.getlist("host") != [urlsplit(config.origin).netloc]
            or any(name in request.headers for name in IDENTITY_HEADERS)
            or "content-encoding" in request.headers
        ):
            raise HTTPException(400, "Invalid request")

    async def boundary(
        request: Request, query: frozenset[str] | None = frozenset(), *, origin: str | None = None
    ) -> None:
        # Query strings are refused unless the route names the keys it accepts, once each.
        # `None` says the route reads the query itself, and only the provider callbacks do:
        # what arrives there is written by Google, GitHub or Microsoft, not by this
        # application, and a client that refuses parameters it did not expect refuses the
        # provider's own success (RFC 6749, section 4.1.2). Those routes check their keys in
        # their own handlers, where a refusal can say which arrived instead of failing before
        # anything is read. A post carries this deployment's own origin, exactly, except at a
        # route that names the one other origin it takes: the Entra consent's sign-in
        # callback, which Microsoft's own page posts (#678).
        await _query(request, query)
        if "authorization" in request.headers:
            # Authenticate only to attribute the rejected attempt. Bearer
            # credentials never substitute for a human session or CSRF proof.
            identity = await identity_for(request, runtime, "human")
            if not request.url.path.startswith("/monitor/"):
                await run_in_threadpool(runtime.reject, identity, "INVALID_IDENTITY")
            raise HTTPException(403, "Human session required")
        await _rest(request)
        if request.method == "POST" and request.headers.getlist("origin") != [
            origin or config.origin
        ]:
            raise HTTPException(403, "Invalid origin")

    async def token_boundary(request: Request, query: frozenset[str] = frozenset()) -> None:
        """The boundary for a personal access token: no Origin or CSRF, which defend a cookie a
        browser sends on its own, and never beside a session cookie."""
        if config.cookie("session") in cookies(request):
            raise HTTPException(400, "Invalid request")
        await _query(request, query)
        await _rest(request)

    async def form(request: Request, max_bytes: int = 16384) -> dict[str, str]:
        await boundary(request)
        if request.headers.getlist("content-type") != ["application/x-www-form-urlencoded"]:
            raise HTTPException(400, "Invalid request")
        raw = bytearray()
        try:
            with anyio.fail_after(5):
                async for part in request.stream():
                    raw.extend(part)
                    if len(raw) > max_bytes:
                        raise ValueError
            pairs = parse_qsl(
                raw.decode("utf-8"),
                keep_blank_values=True,
                strict_parsing=True,
                encoding="utf-8",
                errors="strict",
                max_num_fields=8,
            )
            if len({key for key, _ in pairs}) != len(pairs):
                raise ValueError
            return dict(pairs)
        except (ValueError, TimeoutError):
            raise HTTPException(400, "Invalid request") from None

    async def session_for(
        request: Request, query: frozenset[str] = frozenset()
    ) -> tuple[Session, str]:
        await boundary(request, query)
        values = cookies(request)
        from execbound.directory_store import load_rechecked

        # A directory session back after more than the grace away is rechecked, not refused,
        # before it loads; with no directory configured this is `load_session` itself.
        session = await run_in_threadpool(
            load_rechecked, runtime, config.directory, values.get(config.cookie("session"), "")
        )
        if session.renewal_due:
            # A directory session is rechecked against its provider whenever its renewal is
            # due, which is `RENEW_AFTER` (seven and a half minutes) after it was last
            # extended, and only then. It is due whether or not the row could move: a session
            # already at its two-day end cannot be extended, and is still rechecked. This costs
            # one call to the customer's directory about every seven and a half minutes of
            # continuous use (`recheck_session` itself asks the directory at most once per
            # `RECHECK_INTERVAL`) and one indexed read for every other kind of session. What it
            # buys is that an account disabled in the directory loses the console here rather
            # than at the end of the two days a session may be renewed for.
            if config.directory is not None:
                from execbound.directory_store import recheck_session

                await run_in_threadpool(recheck_session, runtime, config.directory, session)
            if session.renewed and session.account_id is None:
                request.state.session_renewal = session.expires_at
        csrf = values.get(config.cookie("csrf"), "")
        if not verify_csrf(session, csrf):
            raise HTTPException(403, "Invalid session")
        return session, csrf

    async def mutation(
        request: Request, max_bytes: int = 16384
    ) -> tuple[Session, str, dict[str, str]]:
        session, csrf = await session_for(request)
        values = await form(request, max_bytes)
        if not hmac.compare_digest(values.get("csrf", "").encode(), csrf.encode()):
            if not request.url.path.startswith("/monitor/"):
                await run_in_threadpool(runtime.reject, session.identity, "INVALID_CSRF")
            raise HTTPException(403, "Invalid request")
        return session, csrf, values

    return RequestGuards(
        cookies=cookies,
        boundary=boundary,
        form=form,
        session_for=session_for,
        mutation=mutation,
        token_boundary=token_boundary,
    )


def human_router(runtime: Runtime, config: HumanConfig) -> APIRouter:
    routes = APIRouter()
    guards = request_guards(runtime, config)

    @routes.get("/login")
    async def login(request: Request) -> Response:
        await guards.boundary(request, frozenset({"review", "setup"}))
        if request.query_params.get("setup") not in {None, "1"}:
            raise HTTPException(400, "Invalid request")
        csrf = secrets.token_urlsafe(32)
        hint = await run_in_threadpool(directory_hint, runtime, config, guards.cookies(request))
        if hint is not None:
            # `form-action` governs the redirect a form submission follows, so the one button
            # on this page that leaves for a customer's directory needs that directory's host
            # named in this response's policy. The value comes from the provider's row, which
            # a discovery fetch validated as https at registration, and never from a request.
            request.state.form_action = (hint["origin"],)
        return remember(
            request,
            login_page(
                config,
                csrf,
                runtime=runtime,
                directory=hint,
                setup=request.query_params.get("setup") == "1",
            ),
            config,
            runtime,
        )

    @routes.post("/session")
    async def start(request: Request) -> RedirectResponse:
        values = await guards.form(request)
        csrf = guards.cookies(request).get(config.cookie("login"), "")
        if (
            set(values) != {"credential", "csrf"}
            or not re.fullmatch(r"[A-Za-z0-9_-]{43}", csrf)
            or not hmac.compare_digest(csrf.encode(), values.get("csrf", "").encode())
        ):
            raise HTTPException(403, "Invalid request")
        try:
            runtime.limiter.refuse("client", client_key(request))
            selector = credential_selector(values["credential"])
            if selector is not None:
                runtime.limiter.refuse("login", selector)
        except RateLimited as exc:
            raise HTTPException(
                429, "Too many attempts", headers={"Retry-After": str(exc.retry_after)}
            ) from None
        try:
            identity = await run_in_threadpool(authenticate, runtime.db, values["credential"])
        except AuthenticationFailed as failure:
            await run_in_threadpool(
                record_failure, runtime.db, "human", failure, runtime.clock.now()
            )
            raise HTTPException(401, "Invalid credentials") from None
        if identity.kind == "AGENT":
            await run_in_threadpool(runtime.reject, identity, "INVALID_IDENTITY")
            raise HTTPException(403, "Human credential required")
        granted = await run_in_threadpool(
            issue_session,
            runtime.db,
            identity,
            clock=runtime.clock,
            label=device_label(request.headers.get("user-agent")),
        )
        return session_response(
            config, runtime, granted, destination(request, config, runtime, landing(identity.kind))
        )

    @routes.post("/session/logout")
    async def logout(request: Request) -> RedirectResponse:
        session, _, values = await guards.mutation(request)
        if set(values) != {"csrf"}:
            raise HTTPException(400, "Invalid request")
        await run_in_threadpool(revoke_session, runtime.db, session, clock=runtime.clock)
        response = RedirectResponse("/login", status_code=303)
        for name in ("session", "csrf", "account"):
            response.delete_cookie(
                config.cookie(name), secure=config.secure, httponly=True, samesite="strict"
            )
        return response

    # The classic page (#333): the server-rendered approval page, which the
    # console's own approval route links from its error boundary and every approval
    # notification links from its footer, so a phone whose console does not load, or that
    # blocks scripts, still decides. The console answers `/approvals/{approval_id}`.
    async def classic_approval(
        request: Request, approval_id: str, scope: tuple[ApprovalLinks, str] | None
    ) -> Response:
        """The classic page at its plain address or, given `scope`, at the workspace-scoped one:
        the loaded plugin's approval links and the workspace the address names, whose review
        step runs before the page (#496)."""
        try:
            session, csrf = await guards.session_for(request)
        except SessionError as exc:
            if exc.code == "MFA_REQUIRED" and canonical(request.url.path, runtime.plugins):
                return remember_path(
                    RedirectResponse("/mfa", status_code=303), config, runtime, request.url.path
                )
            if exc.code != "INVALID_SESSION":
                raise
            return RedirectResponse(
                login_location(request.url.path, runtime.plugins), status_code=303
            )
        if session.identity.kind not in {"HUMAN_APPROVER", "ADMIN"}:
            raise HTTPException(403, "Approver session required")
        try:
            identifier = UUID(approval_id)
        except ValueError:
            raise HTTPException(404, "Not found") from None
        if str(identifier) != approval_id:
            raise HTTPException(404, "Not found")
        if scope is not None:
            links, tenant_id = scope
            try:
                tenant = UUID(tenant_id)
                if str(tenant) != tenant_id:
                    raise ValueError
            except ValueError:
                raise HTTPException(404, "Not found") from None
            entry = await links.review(
                request, runtime, config, session, csrf, tenant, identifier, True
            )
            if entry is not None:
                return entry
        rows = await run_in_threadpool(
            records, runtime, session, approval_id=identifier, reviewing=True
        )
        if not rows or not rows[0]["approval"]:
            # Outside the approver's scope or unknown: the same answer either way.
            raise HTTPException(404, "Not found")
        row = rows[0]
        approval = row["approval"]
        stop = await run_in_threadpool(active_stop, runtime, session)
        mode = await run_in_threadpool(tenant_mode, runtime, session)
        # A signal fact's producer, by its registered label, as the console names it.
        signal_labels = await run_in_threadpool(
            signal_source_labels, runtime, session, signal_sources(row)
        )
        now = runtime.clock.now()
        decisions = row["decisions"]
        mine = [d for d in decisions if d["principal_id"] == session.identity.principal_id]
        required = int(approval.get("required_approvers", 1) or 1)
        recorded = sum(1 for d in decisions if d["decision"] == "APPROVE")
        if approval["state"] != "PENDING" or row["state"] != "PENDING_APPROVAL":
            status = "settled"
        elif mine:
            status = "decided"
        elif now >= approval["expires_at"]:
            status = "expired"
        elif stop is not None:
            status = "paused"
        else:
            status = "pending"
        row["state_token"] = None
        if status == "pending" and now < session.expires_at:
            row["state_token"] = _form_state(config, session, csrf, row, "approval.decide", runtime)
        return _page(
            "approval.html",
            service=config.service,
            title="Approval",
            session=session,
            csrf=csrf,
            row=row,
            approval=approval,
            frozen=row["frozen_model"],
            signal_labels=signal_labels,
            status=status,
            can_decide=row["state_token"] is not None,
            own_decision=mine[0]["decision"] if mine else None,
            decisions=decisions,
            quorum_text=f"{recorded} of {required} approvals recorded" if required > 1 else None,
            expires_in=time_left((approval["expires_at"] - now).total_seconds()),
            deadline_clock=deadline_clock(row),
            obligations=list(approval["obligation_ids"]),
            stop=stop,
            mode=mode,
        )

    @routes.get("/approvals/{approval_id}/classic")
    async def approval_detail(request: Request, approval_id: str) -> Response:
        return await classic_approval(request, approval_id, None)

    # The workspace-scoped classic address exists only where a loaded plugin's approval links
    # build and open one (#496), as the console's own scoped address does.
    approval_links = runtime.plugins.approval_links
    if approval_links is not None:

        @routes.get("/workspaces/{tenant_id}/approvals/{approval_id}/classic")
        async def scoped_approval_detail(
            request: Request, tenant_id: str, approval_id: str
        ) -> Response:
            return await classic_approval(request, approval_id, (approval_links, tenant_id))

    async def bound_record(
        request: Request, audience: Audience
    ) -> tuple[Session, dict[str, str], dict[str, Any]]:
        session, csrf, values = await guards.mutation(request)
        try:
            row = await run_in_threadpool(
                continuation_row,
                runtime,
                config,
                session,
                csrf,
                values.get("state", ""),
                audience,
            )
        except InvalidContinuation:
            await run_in_threadpool(runtime.reject, session.identity, "INVALID_CONTINUATION")
            raise HTTPException(400, "Invalid continuation") from None
        return session, values, row

    @routes.post("/approvals/{approval_id}/decide")
    async def decide(request: Request, approval_id: str) -> RedirectResponse:
        session, values, row = await bound_record(request, "approval.decide")
        if session.identity.kind not in {"HUMAN_APPROVER", "ADMIN"}:
            raise HTTPException(403, "Approver session required")
        comment = values.get("comment", "").strip()
        if (
            set(values) - {"csrf", "state", "decision", "comment"}
            or {"csrf", "state", "decision"} - set(values)
            or values["decision"] not in {"APPROVE", "DENY"}
            or len(comment) > 500
            or not row["approval"]
            or str(row["approval"]["approval_id"]) != approval_id
        ):
            raise HTTPException(400, "Invalid request")
        try:
            await run_in_threadpool(
                decide_approval,
                runtime.db,
                session.identity,
                row["approval"]["approval_id"],
                "APPROVE" if values["decision"] == "APPROVE" else "DENY",
                runtime.clock,
                authority_check=guard(session),
                catalog=runtime.catalog,
                comment=comment or None,
            )
        except ExecutionError as exc:
            if exc.code == "TENANT_STOPPED":
                raise HTTPException(423, "Emergency stop active") from None
            if exc.code == "INVALID_COMMENT":
                raise HTTPException(400, "Invalid comment") from None
            raise
        log_event(
            "approval.decided",
            tenant_id=session.identity.tenant_id,
            principal_id=session.identity.principal_id,
            approval_id=row["approval"]["approval_id"],
            decision=values["decision"],
        )
        return RedirectResponse("/approvals", status_code=303)

    def guard(session: Session) -> AuthorityCheck:
        return authority_guard(runtime, session)

    return routes
