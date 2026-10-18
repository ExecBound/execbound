# SPDX-License-Identifier: AGPL-3.0-only
"""The two hooks: what Arcade asks before it acts, and what it states afterwards.

See docs/ARCADE.md, The pre hook and The post hook. Both routes are **translators**. Each
authenticates the caller under the `checked_request` discipline `surfaces/http.py`'s agent
routes use and turns its hook into a wire body the kernel already defines — an
`ActionRequest` for `Runtime.execute`, an `OutcomeReport` for `Runtime.report`, the same two
methods `POST /v1/execute` and `POST /v1/executions/{id}/outcome` call. Neither evaluates
policy and neither opens a transaction of its own around a decision: nothing is decided,
dispatched or settled except through those two methods. What they touch besides is the
correlation row, the frozen plan the post path reads to compare a report against, and the
tenant's chain, where a contradiction is recorded. The only `OK` the pre hook gives without
asking the kernel is a toolkit the operator declared ungoverned; otherwise `OK` rests on a
positive fact about the kernel's answer, and the answers that fact does not cover fall
through to a refusal.

The one state they keep of their own is the correlation row `store.py` writes: opened
before the kernel call and completed after it, so `OK` on a grant rests on the kernel's
answer **and** on this Arcade execution id's own row holding that grant's report secret.
That is the duplicate-delivery rule, and it is what refuses a second Arcade id adopted onto
one grant, a row an abandoned deadline left open and a row a crash left uncompleted. It is
also the only route from a post hook to an execution: the execution a report settles comes
from that row and from nothing the post hook sent, because a mapping chosen from a field the
caller supplies would be caller input deciding which execution settles. The post hook's own
`tool` picks the declaration a reported `inputs` object is measured against, which is a
comparison and reaches no kernel call; its `context` selects nothing at all.

**The two routes answer opposite kinds of thing, and the asymmetry is the rule.** On the
way in, an answer is better than an error, because an answer blocks: the pre hook turns
every refusal it can make into one of the three hook codes. On the way out, an error is
better than an answer, because an error is retried: the post hook answers `OK` for anything
it can decide, a body it could not read included, and lets a capacity refusal and a
dependency failure travel as the 429 and 5xx that make Arcade redeliver a settlement.

The body rule is the monitoring intake's rather than the agent routes'. A platform
ExecBound does not control sends `application/json; charset=utf-8`, which
`surfaces/http.read_body` refuses, and the published contract does not retry a 4xx — so the
execution would never settle. `read_body` and what the agent routes accept are unchanged:
widening a security surface to fit somebody else's header would be a change for no reason
of its own. The post hook reads under its own byte bound as well, `post_bytes`, because it
carries whatever the tool returned and a 16 KiB refusal would be a second, quieter wedge.
"""

import asyncio
import json
import re
from functools import partial

import anyio
from fastapi import APIRouter, HTTPException, Request
from starlette.concurrency import run_in_threadpool
from starlette.responses import JSONResponse

from execbound.arcade import store
from execbound.arcade.map import GovernedCall, ToolMap, ToolMapError, UngovernedToolkit
from execbound.arcade.models import (
    HookResult,
    InvalidHook,
    PostHookRequest,
    parse_post_hook,
    parse_pre_hook,
)
from execbound.execution.models import UNSETTLED, ExecutionError, ExecutionView
from execbound.identity import Identity
from execbound.requests import ActionRequest
from execbound.runtime import Runtime
from execbound.secrets import WITHHELD, find_secrets
from execbound.surfaces.http import checked_request, error_status

# The pre hook's own byte bound, separate from `MAX_REQUEST_BYTES` and from the post
# hook's configured one: a decision request carries a tool identity and its inputs.
PRE_HOOK_BYTES = 16 * 1024
# Exactly what the monitoring intake accepts, for exactly its reason.
HOOK_CONTENT_TYPES = frozenset({"application/json", "application/json; charset=utf-8"})
# How long a body may take to arrive, the bound `read_body`, the monitoring intake and the
# human surface each carry. A hook slot and a connection are held while one arrives, so a
# stalled sender must not hold either.
READ_SECONDS = 5
# `ActionRequest.idempotency_key`'s own character class. Arcade's execution id is carried
# verbatim when it already fits and refused when it does not: a digest would make a
# correlation row unreadable beside Arcade's own logs at the moment an operator is
# comparing the two, and refusal is this deployment's default for anything unrecognized.
_IDEMPOTENCY_KEY = re.compile(r"[A-Za-z0-9._:-]{1,128}")
# The two `ExecutionError` codes `surfaces/http.error_status` answers with 429, which is
# what Arcade's rate-limit code means. A shared impact ceiling is not among them: it denies,
# and telling a caller which rule stopped it is a channel no other caller of this kernel
# gets.
_CAPACITY = frozenset({"BUSY", "RATE_LIMITED"})
# What a control point's `success: false` states: the call did not succeed and whether the
# vendor acted is not established. It is not `FAILED_NOT_EXECUTED`, which claims the vendor
# was never reached — a free-form `execution_error` supports no such claim, because a tool
# that got a 500 from a vendor may well have mutated it first.
_FAILURE = "FAILED_EFFECT_UNKNOWN"


def _refused(error: ExecutionError) -> HookResult:
    """The kernel's refusal as a hook code, on the error's own stable spelling."""
    if error.code in _CAPACITY:
        return HookResult("RATE_LIMIT_EXCEEDED", error.code)
    return HookResult("CHECK_FAILED", error.code)


def _decided(view: ExecutionView, approvals: str | None, held: bool) -> HookResult:
    """The kernel's answer as a hook code: the pre hook's table, keyed on what it returned.

    `OK` requires a positive fact and there are two of them. A live grant is one: impact is
    reserved, the target is claimed, and the act it describes can be settled by this Arcade
    execution because this Arcade execution's own correlation row holds the grant's report
    secret — `held`, either because this answer minted it or because an earlier delivery of
    the same Arcade id already retained it. `OBSERVED` is the other: observe-only records
    what ExecBound would decide while the action proceeds, and permitting is what that mode
    means.

    `held` is what refuses the second Arcade id adopted onto a granted intent, the row an
    abandoned deadline left open and the row a crash left uncompleted, with no special case
    for any of them: none of the three holds a secret, so none is `OK`. The residual is
    limitation 9 — such a grant goes unreported and waits for the administrator exit — and
    what this refusal buys is that the platform is not told to act on it.

    A grant object is still required beside `held`, and that conjunct is not spare: a retry
    after the frozen plan has expired is answered `DISPATCH_COMMITTED` with no grant at all
    while the row still holds the first delivery's secret, and `OK` there would describe an
    act whose plan no longer authorizes it.

    An emergency stop is refused ahead of both facts, because a hard denial wins over a
    permit: the stop branch of admission answers a known idempotency key with the row's own
    view, which for a tenant that was observing is an `OBSERVED` state carrying the flag.
    """
    if view.tenant_stopped:
        return HookResult("CHECK_FAILED", _message("TENANT_STOPPED", view))
    if view.state == "DISPATCH_COMMITTED" and view.checkpoint is not None and held:
        return HookResult("OK")
    if view.state == "OBSERVED":
        return HookResult("OK")
    if view.state == "PENDING_APPROVAL" and approvals:
        # What progresses an approved execution here is the agent's next tool call,
        # arriving as another pre hook, so the page a human decides on is the useful
        # thing to name; the continuation the runtime mints is discarded rather than
        # passed on.
        return HookResult("CHECK_FAILED", f"{_message(view.state, view)} approvals={approvals}")
    return HookResult("CHECK_FAILED", _message(view.state, view))


def _message(code: str, view: ExecutionView) -> str:
    """A stable ExecBound code and the execution id it is about, and nothing else."""
    return f"{code} execution={view.execution_id}"


def _request(call: GovernedCall, execution_id: str) -> bytes:
    """The wire body the kernel already defines, built from the operator's declaration.

    The extension names no run, and the one context field it fills is the incident id the
    map extracted from a declared input, which is a claim the kernel checks against the
    incident table rather than a fact the platform asserts. `ClaimedContext`'s other four
    fields — `severity`, `environment`, `role` and `criticality` — stay unset, because a
    control point asserting one of those would be a caller-supplied fact reaching policy
    through a surface that evaluates none. Anything this model refuses is left to raise
    rather than caught: every field it is given has already been through the map's own
    model or the check above, the deployment boundary answers `CHECK_FAILED` for an error as
    it does for a refusal, and a handler no test could reach is a guard nothing exercises.
    """
    request = ActionRequest(
        operation_ref=call.operation_ref,
        target=call.target,
        arguments=call.arguments,
        idempotency_key=execution_id,
        claimed_context=call.claimed_context,
    )
    return request.model_dump_json().encode()


async def _framed(request: Request, runtime: Runtime, identity: Identity) -> None:
    """The monitoring intake's content-type rule, which both hooks take unchanged.

    It is the frame rather than the body, so it is a 400 on both routes: the published
    contract answers 400 for a malformed request, a misconfigured header is not a report
    ExecBound failed to read, and retrying it would change nothing. What the post route
    treats as silence is the body inside a frame it accepted.

    Two cases reach `!= 1` and only one of them reaches it from a request. A request sending
    no content-type at all is refused here. A request sending the header twice never gets
    this far: `checked_request` refuses more than one `content-type` on every route it
    guards, ahead of this one, so the `> 1` half is unreachable through either hook. It is
    written as `!= 1` rather than as an emptiness test because the alternative — reading
    `content_types[0]` and ignoring the rest — would be the wrong answer if that upstream
    refusal ever moved. The hook tests pin both halves: one sends no content-type and
    reaches this, one sends two and is shown never to.
    """
    content_types = request.headers.getlist("content-type")
    if len(content_types) != 1 or content_types[0].lower() not in HOOK_CONTENT_TYPES:
        await run_in_threadpool(runtime.reject, identity)
        raise HTTPException(400, "Invalid hook request")


async def _body(request: Request, limit: int) -> bytes:
    """The bytes, under this route's own byte bound and the shared arrival deadline.

    Raises rather than answering: what an unreadable body means is the caller's, and the
    two routes answer it differently.
    """
    raw = bytearray()
    with anyio.fail_after(READ_SECONDS):
        async for part in request.stream():
            if len(raw) + len(part) > limit:
                raise ValueError("Hook body past its bound")
            raw.extend(part)
    return bytes(raw)


async def _read_hook(request: Request, runtime: Runtime, identity: Identity, limit: int) -> bytes:
    """The pre hook's body: a frame or a body this route cannot read is a 400."""
    await _framed(request, runtime, identity)
    try:
        return await _body(request, limit)
    except (TimeoutError, ValueError):
        await run_in_threadpool(runtime.reject, identity)
        raise HTTPException(400, "Invalid hook request") from None


async def _pre(runtime: Runtime, tools: ToolMap, identity: Identity, raw: bytes) -> HookResult:
    """One pre hook decided: the map's refusals, then the kernel's answer or its refusal."""
    try:
        hook = parse_pre_hook(raw)
    except InvalidHook:
        # Audited as the agent route audits a body it could not read. The map's own
        # refusals below are not: no kernel call is made for them, so there is no
        # execution to reject, and an undeclared tool refused on every call would put the
        # project's tool traffic behind the tenant's audit head.
        await run_in_threadpool(runtime.reject, identity)
        return HookResult("CHECK_FAILED", "INVALID_HOOK")
    try:
        decided = tools.decide(
            toolkit=hook.tool.toolkit,
            name=hook.tool.name,
            version=hook.tool.version,
            inputs=hook.inputs,
            metadata=hook.tool.metadata,
        )
    except ToolMapError as refusal:
        # The map's codes carry nothing the caller sent, which is what makes them safe to
        # hand back to the agent that wrote the inputs.
        answer = HookResult("CHECK_FAILED", str(refusal))
        # Recorded as a correlation row and deliberately not as an audit event (#339).
        # Before this, a governed call the map refused left nothing anywhere, so a tenant
        # counting its own refused governed calls out of `arcade_hooks` undercounted by
        # exactly the class of refusal a vendor's schema drift produces. The row is a plain
        # insert under the tenant fence: appending an event instead would put the project's
        # refused tool traffic behind the tenant's audit head, which is the cost the
        # ungoverned branch below refuses to pay and which this must not start paying
        # either. What the row carries is the tool identity and the reported metadata,
        # which is what tells drift from a bad call; the code itself is not stored, exactly
        # as it is not stored for the kernel's own refusals.
        #
        # An id outside the kernel's class cannot key a row, and the key's third part is
        # the unusable thing, so that one is answered and not recorded rather than given a
        # second key nobody else uses. It is the only refusal on this route that stays
        # invisible, and the guide says so.
        if not _IDEMPOTENCY_KEY.fullmatch(hook.execution_id):
            return answer
        # `_OPEN` ends `ON CONFLICT DO NOTHING`, so this cannot wedge a later legitimate
        # delivery of the same Arcade id: that delivery's own open is a no-op and the
        # kernel path completes the row this left.
        await run_in_threadpool(store.open_hook, runtime.db, identity, hook, runtime.clock)
        return await run_in_threadpool(
            store.refused, runtime.db, identity, hook.execution_id, answer
        )
    if isinstance(decided, UngovernedToolkit):
        # The operator's standing decision: no kernel call, no execution row, no
        # reservation and no audit event. Limitation 7 records what that costs.
        return HookResult("OK")
    if not _IDEMPOTENCY_KEY.fullmatch(hook.execution_id):
        return HookResult("CHECK_FAILED", "UNSUPPORTED_EXECUTION_ID")
    body = _request(decided, hook.execution_id)
    # Opened and committed before the kernel is asked anything, so the grant a crash between
    # the two writes strands is refused at the next hook rather than granted to whoever asks
    # next. A failure to open is left to raise: the boundary answers `CHECK_FAILED` for an
    # error as it does for a refusal, and a kernel call with no row to complete afterwards is
    # the state this order exists to prevent.
    await run_in_threadpool(store.open_hook, runtime.db, identity, hook, runtime.clock)
    try:
        view = await asyncio.wait_for(
            # Abandoned rather than cancelled, because a thread cannot be cancelled: the
            # decision may still commit, which is retained uncertainty with an
            # administrator exit rather than a refund. Threading a cancellation token into
            # the kernel would be a new way for a caller to influence a fenced transaction.
            # No test here distinguishes this flag: on the installed anyio the deadline
            # expires either way. It is written because the default is documented to make
            # the waiting task ignore its own cancellation until the thread returns, and a
            # bound that rests on undocumented behaviour is not a bound.
            anyio.to_thread.run_sync(
                partial(runtime.execute, identity, body), abandon_on_cancel=True
            ),
            tools.block.deadline_seconds,
        )
    except TimeoutError:
        # Deliberately not the retryable code: an abandoned decision may hold the intent
        # and the target claim, so inviting an immediate retry would invite a refusal. The
        # row is left as it was opened, because nothing answered: that is the same shape the
        # crash leaves, and it refuses the next delivery of this Arcade id, and any other
        # Arcade id admission adopts onto the same unsettled execution, by the one condition
        # rather than by a second rule.
        return HookResult("CHECK_FAILED", "DEADLINE_EXCEEDED")
    except ExecutionError as refusal:
        return await run_in_threadpool(
            store.refused, runtime.db, identity, hook.execution_id, _refused(refusal)
        )
    return await run_in_threadpool(
        store.complete,
        runtime.db,
        identity,
        hook.execution_id,
        view,
        partial(_decided, view, runtime.approval_url),
    )


def _report(hook: PostHookRequest, secret: str, runtime: Runtime) -> bytes:
    """The post hook's settlement table as the wire body the outcome route already defines.

    Three of the table's five rows are decided here and the other two never reach it. A
    stated success settles `EXECUTED`; a stated failure settles `FAILED_EFFECT_UNKNOWN`
    with reason `REPORTED_FAILURE`, which costs the caller exactly what the success costs —
    the same confirmed impact, the same claim held to the act window, the same closed row —
    so there is nothing to be gained by choosing one and nothing to lie about. An absent
    `success` is **silence**: it states no result, so it is reported `UNKNOWN`, which
    settles nothing and leaves the retained uncertainty no post hook at all leaves. Writing
    a failure into a tamper-evident history on it would say the control point reported
    something it did not, and would make saying nothing the cheapest way to close a row.

    `execution_code` and `execution_error` reach no field of this body. They are the
    platform's own strings, retained inert on the correlation row for a person to read, and
    `success: true` beside an `execution_error` is a platform message inconsistent with
    itself rather than a signal: it decides its row as the table says, appends no audit
    event and changes no settlement, and it changes nothing about what the tenant is charged
    either, because both readings of that body confirm the same impact.

    The reported time is the extension's own clock and never the platform's, because the
    body carries no time and a settlement's evidence names when the reporter says it spoke.
    """
    outcome = "UNKNOWN" if hook.success is None else "EXECUTED" if hook.success else _FAILURE
    reason = None if hook.success is None else "EXECUTED" if hook.success else "REPORTED_FAILURE"
    body: dict[str, object] = {
        "report_secret": secret,
        "outcome": outcome,
        "reported_at": runtime.clock.now().isoformat(),
    }
    if reason is not None:
        body["reason"] = reason
    return json.dumps(body).encode()


def _differs(tools: ToolMap, hook: PostHookRequest, frozen: ActionRequest | None) -> bool:
    """Whether this report's own inputs derive something other than the decision's request.

    `inputs` is optional on a post hook, so its absence establishes nothing and claims
    nothing; its presence and difference establishes that what executed is not what was
    decided. The pre hook's `inputs` are deliberately not retained — what the decision was
    taken on is the frozen plan — so the comparison is against the frozen `ActionRequest`,
    re-deriving the selection through the same declaration the pre hook was decided under.
    A tool the map now refuses, or one no declaration governs, differs too: none of those
    derives the request this execution froze.

    Two things it cannot see are stated here rather than left to be found.

    The first is a declared input the declaration maps to nothing. Such a key reaches the
    vendor and derives no part of the request, so two hooks differing only there derive the
    same selection and this answers `False`. The declaration's own `inputs` allowlist is
    what bounds that key's existence.

    The second is narrower and is in the comparison rather than in the map. `Arguments` is a
    model, so `!=` is Python's equality over its mapping, and Python holds `True == 1`: a
    mapped argument reported as `1` where the decision froze `true` compares equal here and
    records nothing, while the kernel's own hashes of the two differ, because they are taken
    over canonical JSON where `true` and `1` are different bytes. `Arguments.__hash__`
    carries the same note at its source. What is lost is one contradiction and nothing about
    what settles: a post hook settles the execution its correlation row names, on the secret
    that row holds, and its reported `inputs` reach no part of that.

    The reported `metadata` is deliberately not passed to the map: the `expect` comparison
    is the pre hook's denial and not a fact about these inputs, and a report whose
    self-description drifted would otherwise be recorded as an inputs contradiction.
    """
    if hook.inputs is None or frozen is None:
        return False
    try:
        decided = tools.decide(
            toolkit=hook.tool.toolkit,
            name=hook.tool.name,
            version=hook.tool.version,
            inputs=hook.inputs,
        )
    except ToolMapError:
        return True
    if isinstance(decided, UngovernedToolkit):
        return True
    return (
        decided.operation_ref,
        decided.target,
        decided.arguments,
        decided.claimed_context,
    ) != (frozen.operation_ref, frozen.target, frozen.arguments, frozen.claimed_context)


def _contradicted(tools: ToolMap, hook: PostHookRequest, correlated: store.Correlated) -> list[str]:
    """The contradictions this arrival shows, in the order docs/ARCADE.md lists them.

    A denial is a pre hook this deployment refused whose tool ran anyway, which is either a
    fail-open configuration or a bypass — evidence of a configuration problem and never a
    proven bypass, and the rule that turns it into a finding belongs to the monitoring
    track. The recorded answer is what decides, so a row the extension never answered on —
    one an abandoned deadline or a crash left open, whose `decision` is null — shows no
    denial here: it records no answer to have contradicted.
    """
    found = []
    if correlated.decision is not None and correlated.decision != "OK":
        found.append("DENIED_CALL")
    if _differs(tools, hook, correlated.frozen_request):
        found.append("INPUTS_DIFFER")
    return [name for name in found if name not in correlated.recorded]


def _contradiction_payload(
    name: str, hook: PostHookRequest, correlated: store.Correlated
) -> dict[str, object]:
    """What the chain retains about one contradiction: identifiers and inert platform text.

    No `inputs` value is in it, of either hook. What the reported tool identity is worth is
    that it is the platform's own description of what ran, bounded by the map's name
    patterns, and it is the one place the post hook's tool identity is retained at all.

    The name patterns still admit text shaped like a credential, and an event the export's
    secret check flags fails the tenant's export at that window for good. Such an identity is
    withheld and the contradiction appended without it: refusing the hook instead would lose
    the one record that a denied call ran anyway, which is the record this event exists for.
    """
    reported = (hook.tool.toolkit, hook.tool.name, hook.tool.version)
    payload: dict[str, object] = {"contradiction": name}
    if find_secrets(reported, limit=1):
        payload["tool_identity"] = WITHHELD
    else:
        payload["toolkit"], payload["tool_name"], payload["tool_version"] = reported
    if correlated.execution_id is not None:
        payload["execution_id"] = str(correlated.execution_id)
    if correlated.operation_id is not None:
        payload["operation_id"] = str(correlated.operation_id)
    if correlated.plan_hash is not None:
        payload["plan_hash"] = correlated.plan_hash
    return payload


async def _post(runtime: Runtime, tools: ToolMap, identity: Identity, raw: bytes) -> None:
    """One post hook applied: the four arrivals that record, and the three that report.

    Nothing here answers the platform. The route answers `OK` for every path that returns
    from this function, and what the platform sees differently is an error that escapes it:
    the `ExecutionError` re-raised below, which is the transport-level 429 or 5xx that
    exists so a settlement Arcade could redeliver is redelivered, and anything unexpected,
    which the application's own handler answers as a 503 for the same reason.

    The order is deliberate. What the platform said is retained on the correlation row
    first, because a body that reached here is a statement whether or not it settles
    anything; the contradictions are appended next, each exactly when it moves the row; and
    the settlement is last, against the execution correlation named and with the secret
    that row holds. A row that names no execution, or holds no usable secret, settles
    nothing and is not an error: a refused pre hook, an observing tenant's `OBSERVED` row,
    a row an abandoned decision left open and a row whose report window has closed are all
    of that shape.
    """
    try:
        hook = parse_post_hook(raw)
    except InvalidHook:
        # Silence, recorded as bounded as every refused request in the kernel is recorded:
        # this body names no Arcade execution, so there is no correlation row to record it
        # on. Refusing with a 400 would be strictly worse — it is not retried, it settles
        # nothing, and it tells the agent its tool call failed when it did not.
        await run_in_threadpool(runtime.reject, identity, "UNREADABLE_REPORT")
        return
    correlated = await run_in_threadpool(store.correlate, runtime.db, identity, hook, runtime.clock)
    if correlated is None:
        # The orphan, including a post hook that overtook its own pre hook: nothing
        # documents ordering, and the pre hook that follows decides normally because this
        # wrote nothing it could adopt.
        await run_in_threadpool(runtime.reject, identity, "UNCORRELATED_REPORT")
        return
    for name in _contradicted(tools, hook, correlated):
        await run_in_threadpool(
            store.contradiction,
            runtime.db,
            identity,
            hook.execution_id,
            name,
            _contradiction_payload(name, hook, correlated),
            runtime.clock,
        )
    if correlated.execution_id is None or correlated.report_secret is None:
        return
    body = _report(hook, correlated.report_secret, runtime)
    try:
        view = await run_in_threadpool(runtime.report, identity, correlated.execution_id, body)
    except ExecutionError as refusal:
        # A refusal the kernel makes about this row — a settled row that is not restating
        # its own settlement, a closed window, a secret that does not authenticate — is
        # permanent and the platform can do nothing with it, so it is answered `OK` and
        # recorded by the kernel's own rejection. A capacity refusal and a dependency
        # failure are neither permanent nor this row's, and those are the ones that travel.
        if error_status(refusal) == 429 or error_status(refusal) >= 500:
            raise
        return
    if view.state not in UNSETTLED:
        await run_in_threadpool(
            store.settled, runtime.db, identity, hook.execution_id, runtime.clock
        )


def _answer(result: HookResult) -> JSONResponse:
    """Always 200: an evaluated hook is an answer, whichever of the three codes it is."""
    return JSONResponse(result.body(), status_code=200)


def hook_slots_for(in_flight: int, concurrency: int) -> int:
    """Concurrent hooks this surface admits, derived from the two bounds that sit above it.

    It is one below the smaller of the application's own in-flight bound and the runtime's
    concurrency, and never below one. Deriving it is the point: written down as a constant
    equal to the application's bound, this limiter could not refuse anything. `create_app`'s
    outermost middleware acquires that bound before `call_next` and answers a bare 429 whose
    body is `{"detail": "Service busy"}` — no hook code in it, and the route never runs — so
    no request reached either hook to find no slot, and both refusals below were paths a
    deployment could not take.

    Below the application's bound, a hook flood meets this surface's own answer instead:
    `RATE_LIMIT_EXCEEDED` with `HOOK_CAPACITY` on the way in, which blocks the tool call
    under either of Arcade's failure modes, and a 429 on the way out, which is what makes
    Arcade redeliver a settlement. The deployment boundary rewrites the application's bare
    429 into the same pre-hook answer, and that rewrite is what covers a process serving
    only the hooks; a process serving the gateway and the hooks together has no boundary in
    front of it, and this bound is what answers there.

    Below the runtime's concurrency, a hook flood leaves the semaphore admission and
    reporting share a slot, so the control point's traffic does not shut a co-hosted
    gateway's own agent routes out of the kernel. `BUSY` still reaches a hook — it is what a
    hook meets when other traffic has filled the runtime — and the pre hook's table still
    maps it to the retryable code.

    The floor is the degenerate deployment, and it is where both sentences above stop
    holding. An application bound or a runtime concurrency of one gives this surface one
    slot, which is equal to that bound rather than below it: the application refuses first
    at the one, and the surface holds the runtime's only slot at the other. A deployment
    that narrow serves hooks one at a time rather than none, which is what the floor is for.
    """
    return max(1, min(in_flight, concurrency) - 1)


def arcade_router(runtime: Runtime, tools: ToolMap, in_flight: int) -> APIRouter:
    """The hook routes one deployment serves, bound to its runtime and its tool map.

    `in_flight` is the application's own capacity bound, passed rather than imported so the
    two numbers cannot drift apart in two modules that do not import each other.
    """
    routes = APIRouter()
    hook_slots = anyio.CapacityLimiter(hook_slots_for(in_flight, runtime.concurrency))

    @routes.post("/pre")
    async def pre(request: Request) -> JSONResponse:
        try:
            identity = await checked_request(request, runtime)
        except ExecutionError as refusal:
            # The surface rate limiter, taken before any lookup or parsing, so a refusal
            # here consumed nothing. A header, credential or principal refusal raises an
            # `HTTPException` instead, and a dependency failure under it reaches the
            # application's own handler; the deployment boundary rewrites both.
            return _answer(_refused(refusal))
        try:
            hook_slots.acquire_nowait()
        except anyio.WouldBlock:
            return _answer(HookResult("RATE_LIMIT_EXCEEDED", "HOOK_CAPACITY"))
        try:
            raw = await _read_hook(request, runtime, identity, PRE_HOOK_BYTES)
            return _answer(await _pre(runtime, tools, identity, raw))
        finally:
            hook_slots.release()

    @routes.post("/post")
    async def post(request: Request) -> JSONResponse:
        # Nothing here converts a refusal into a hook code, which is the opposite of the
        # route above and is deliberate rather than an omission: a post-hook refusal cannot
        # un-execute anything, the vendor has already done whatever it did, and what Arcade
        # does with a `CHECK_FAILED` on a post hook is not documented. What is worth having
        # instead is the retry, so the surface rate limiter's refusal travels as the 429 the
        # application's own handler gives it, and so does the capacity refusal below; both
        # mean this deployment has not settled anything yet.
        identity = await checked_request(request, runtime)
        try:
            hook_slots.acquire_nowait()
        except anyio.WouldBlock:
            raise ExecutionError("BUSY") from None
        try:
            await _framed(request, runtime, identity)
            try:
                raw = await _body(request, tools.block.post_bytes)
            except (TimeoutError, ValueError):
                # An over-bound or unparseable body is silence, not a refusal: the route
                # stops reading at the bound, nothing is settled because nothing was read,
                # and the execution keeps the sweep and the administrator exit it had. No
                # part of what was read is retained or logged.
                await run_in_threadpool(runtime.reject, identity, "UNREADABLE_REPORT")
            else:
                await _post(runtime, tools, identity, raw)
            return _answer(HookResult("OK"))
        finally:
            hook_slots.release()

    return routes
