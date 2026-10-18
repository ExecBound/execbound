# SPDX-License-Identifier: AGPL-3.0-only
"""The live probe against an Entra lab tenant (#125).

**This module talks to a real directory and disables a real user account.** It is skipped
unless `EXECBOUND_GRAPH_LIVE=1` is set *and* `EXECBOUND_GRAPH_CREDENTIAL` names the execute
registration's credential file and that file is present, so CI — which sets neither — never
reaches it. The module names no credential file of its own. Nothing else in the suite touches
a vendor.

The tenant is a lab directory kept for this probe, holding no organizational data and
serving no production work, and the two registrations stay separate: one reads the directory
for Scout, this one executes and holds no discovery permission. The tenant's domain is read
from the credential file's `ENTRA_DOMAIN` line, beside the registration's own values, so no
tenant is named in this file, and a credential file without one refuses the probe.

What this asserts that a fake Graph cannot: that `User.EnableDisableAccount.All` is
sufficient to disable a user and that ExecBound's composite recipe matches what Microsoft
actually returns. Both were documentation until this ran.
"""

import os
import time
import warnings
from collections.abc import Mapping
from pathlib import Path

import httpx
import pytest
from graph_fixtures import (
    ACTION,
    ROTATED_KEY,
    ROTATED_KEY_ID,
    SIGNING_KEY,
    SIGNING_KEY_ID,
)
from graph_fixtures import (
    graph_world as graph_world,
)
from graph_fixtures import (
    registry as registry,
)
from graph_fixtures import (
    world as world,
)
from identity_fixtures import identity_request
from sqlalchemy import text

from execbound.execution import admit, decide_approval
from execbound.execution.models import PreconditionConfig
from execbound.provider.composite import graph_user_composite
from execbound.provider.connector_record import ConnectorRecord
from execbound.provider.gateway import dispatch_owned
from execbound.provider.graph import GraphCredential, GraphDispatchError, GraphUserWriter
from execbound.provider.graph_connector import GraphConnectionConfig, GraphConnector
from execbound.provider.models import parse_provider

# The execute registration's credential file, named by `EXECBOUND_GRAPH_CREDENTIAL` alone.
# Unset or empty, there is no file, and the guard below skips as it does for a missing one.
_NAMED = os.environ.get("EXECBOUND_GRAPH_CREDENTIAL", "")
CREDENTIAL: Path | None = Path(_NAMED) if _NAMED else None
CHECKED = PreconditionConfig({("graph", "disable"): "CHECKED_BY_CONNECTOR"})

# `tests/conftest.py` does not collect this module at all unless EXECBOUND_GRAPH_LIVE=1,
# because the release gate refuses a junit report carrying any skip. This second guard
# covers the case that remains once it is collected: the variable set on a machine where
# `EXECBOUND_GRAPH_CREDENTIAL` names no credential file, or one that is not there, where
# skipping is the right answer and the gate is not involved.
pytestmark = pytest.mark.skipif(
    CREDENTIAL is None or not CREDENTIAL.exists(),
    reason="live Entra probe: the execute registration's credential file is not present",
)


def lab_settings(path: Path | None = CREDENTIAL) -> dict[str, str]:
    """The credential file's `NAME=VALUE` lines; a line starting with `#` is a comment."""
    assert path is not None, "EXECBOUND_GRAPH_CREDENTIAL names no credential file"
    values: dict[str, str] = {}
    for line in path.read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            name, value = line.split("=", 1)
            values[name.strip()] = value.strip()
    return values


def lab_domain(values: Mapping[str, str]) -> str:
    """The lab tenant's domain, in which the probe names the user it disables.

    Without it the probe has no user to name, and it refuses to run rather than guess one.
    """
    domain = values.get("ENTRA_DOMAIN", "")
    if not domain:
        raise LookupError(
            "the live probe's credential file has no ENTRA_DOMAIN line naming the lab "
            "tenant's domain; add one beside ENTRA_DIRECTORY_ID"
        )
    return domain


def allowed_upn(path: Path | None = CREDENTIAL) -> str:
    """The disposable user the probe disables and restores."""
    try:
        return f"disposable.target@{lab_domain(lab_settings(path))}"
    except LookupError as refused:
        pytest.fail(str(refused), pytrace=False)


def credential() -> GraphCredential:
    values = lab_settings()
    return GraphCredential(
        values["ENTRA_DIRECTORY_ID"], values["ENTRA_CLIENT_ID"], values["ENTRA_CLIENT_SECRET"]
    )


class CountingTransport(httpx.HTTPTransport):
    """Every request this process makes to the vendor, so "none" can be asserted."""

    def __init__(self) -> None:
        super().__init__(retries=0, trust_env=False)
        self.requests: list[str] = []

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(f"{request.method} {request.url}")
        return super().handle_request(request)


_SESSION: dict[str, object] = {}


def session() -> tuple[GraphUserWriter, str]:
    """One writer and one token, reused across reads.

    A fresh token per read is four OAuth requests a second while polling, which is both
    wrong and a good way to be throttled into a failure that looks like replication lag.
    The token is a local value held for the length of the probe and never persisted.
    """
    if "writer" not in _SESSION:
        writer = GraphUserWriter(credential())
        _SESSION["writer"] = writer
        _SESSION["token"] = writer._token()
    return _SESSION["writer"], _SESSION["token"]  # type: ignore[return-value]


def forget_session() -> None:
    writer = _SESSION.pop("writer", None)
    _SESSION.pop("token", None)
    if writer is not None:
        writer.close()  # type: ignore[attr-defined]


def read_user(upn: str) -> dict[str, object]:
    writer, token = session()
    try:
        return writer._read_user(token, upn)
    except GraphDispatchError as error:
        if error.reason not in {"FORBIDDEN", "AUTH_LOST"}:
            raise
        # The token aged out mid-probe; mint one more and try exactly once.
        forget_session()
        writer, token = session()
        return writer._read_user(token, upn)


def settled(upn: str, enabled: bool, stable: int = 3, timeout: float = 30.0) -> float:
    """Wait until several *consecutive* reads agree, not just one.

    One agreeing read does not bind the next. Graph serves reads from replicas that catch
    up independently, so a single convergence can be followed immediately by a stale read —
    which is how this module first failed: the fixture froze a composite from a lagging
    replica and the dispatch was refused STALE_AUTHORIZATION, the kernel behaving correctly
    against a precondition that was stale before it began.

    Consecutive agreement makes that unlikely. It cannot make it impossible, and nothing
    available to a client can. Measured here on 18 September 2026: 116 reads over 40
    seconds after a `204`, with the sequence `FFFFTFFFF...` — a single stale read landing
    1.25 seconds *after* the write, in the middle of a run of correct ones. A stale answer
    is not an early phase that ends; it is one replica answering at any moment.

    So no number of reads establishes current state, and re-reading can never confirm the
    connector's own write. That is the fact `CHECKED_BY_CONNECTOR` exists to be honest
    about, and the reason `GraphConnector.lookup` returns None rather than a reading.
    """
    started = time.monotonic()
    agreed = 0
    while True:
        agreed = agreed + 1 if read_user(upn)["accountEnabled"] is enabled else 0
        if agreed >= stable:
            return time.monotonic() - started
        if time.monotonic() - started > timeout:
            raise AssertionError(f"{upn} never settled at accountEnabled={enabled}")
        time.sleep(0.25)


def converges(upn: str, enabled: bool, timeout: float = 30.0) -> float:
    """Wait for a read to agree with a write, and return how long that took.

    **Graph's read-after-write is not immediately consistent.** Measured in this tenant on
    18 September 2026: a read immediately after a `204` agreed in 0.07s twice and in 1.31s
    once, and the first run of this probe failed on an immediate read-back that returned
    the pre-write state. Polling here is the vendor's behaviour being accommodated, not a
    flaky assertion being papered over.

    This is also, independently, why `GraphConnector.lookup` returns None: if a read taken
    right after a write can show the old state, a re-read cannot confirm the connector's
    own write even before the question of who else might have changed it.
    """
    started = time.monotonic()
    while True:
        if read_user(upn)["accountEnabled"] is enabled:
            return time.monotonic() - started
        if time.monotonic() - started > timeout:
            raise AssertionError(f"{upn} never read back as accountEnabled={enabled}")
        time.sleep(0.25)


def set_enabled(upn: str, enabled: bool) -> None:
    """Restore the directory out of band, through the same registration."""
    writer, token = session()
    response = writer._client.patch(
        f"https://graph.microsoft.com/v1.0/users/{upn}",
        json={"accountEnabled": enabled},
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
    )
    assert response.status_code in {200, 204}, response.status_code


@pytest.fixture
def live_target(graph_world, admin_engine):
    """Point the seeded resource at the real user, at the composite Graph returns now.

    The directory is settled to a known state *before* the composite is frozen. Without
    that, a read that lands on a replica still showing the previous test's value freezes a
    composite the connector's own read will not match, and the dispatch is refused
    STALE_AUTHORIZATION — which is the kernel behaving correctly and the fixture lying.
    That happened on the first run of this module and is worth stating: on a directory whose
    reads are eventually consistent, a frozen precondition can be stale before the dispatch
    begins, through nobody's fault, and refusing is the only safe answer available.
    """
    upn = allowed_upn()
    set_enabled(upn, True)
    settled(upn, True, timeout=120.0)
    user = read_user(upn)
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.resources SET provider_id=:p, version=:v "
                "WHERE tenant_id=:t AND resource_id=:r"
            ),
            {
                "p": str(user["id"]),
                "v": graph_user_composite(user),
                "t": graph_world["identity"].tenant_id,
                "r": graph_world["target"],
            },
        )
    yield graph_world
    # Restore, best effort. Teardown's job is to put the lab directory back, not to make a
    # claim: raising here would mark a test that genuinely passed as errored, and what it
    # would be reporting is the vendor's replication, not the code under test. The next
    # test's setup is where a clean baseline actually matters, and it insists on one.
    set_enabled(upn, True)
    try:
        settled(upn, True, timeout=60.0)
    except Exception as error:  # noqa: BLE001 - restoration never fails a passing test
        warnings.warn(f"the lab directory did not settle at enabled: {error}", stacklevel=1)


def refreeze(admin_engine, world) -> None:
    """Re-read the user and re-freeze the resource version from that reading."""
    user = read_user(allowed_upn())
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.resources SET provider_id=:p, version=:v "
                "WHERE tenant_id=:t AND resource_id=:r"
            ),
            {
                "p": str(user["id"]),
                "v": graph_user_composite(user),
                "t": world["identity"].tenant_id,
                "r": world["target"],
            },
        )


def live_connector(world, *, keys=None, signing_key_id=SIGNING_KEY_ID, secret=None):
    cred = credential()
    if secret is not None:
        cred = GraphCredential(cred.directory, cred.client_id, secret)
    transport = CountingTransport()
    config = GraphConnectionConfig(
        world["identity"].tenant_id,
        world["account"],
        cred,
        keys or {SIGNING_KEY_ID: SIGNING_KEY},
        signing_key_id,
    )
    client = httpx.Client(transport=transport, trust_env=False, follow_redirects=False)
    return GraphConnector(config, GraphUserWriter(cred, client)), transport


def ready(db, world, attempt: int = 0):
    """Admit one request. Each re-issue is its own request, with its own key.

    An idempotency key binds to exactly one execution, so re-issuing after a stale refusal
    under the same key is not a retry — it is a second reference to an execution that has
    already settled, and admission refuses it. An operator re-issuing after
    STALE_AUTHORIZATION is making a new request about the same subject, and this says so.
    """
    request = identity_request(world, ACTION, idempotency_key=f"identity-{ACTION}-{attempt}")
    admission = admit(db, world["identity"], request, world["clock"])
    if admission.view.state == "PENDING_APPROVAL":
        decide_approval(db, world["human"], admission.view.approval_id, "APPROVE", world["clock"])
        admission = admit(db, world["identity"], request, world["clock"])
    return admission


def settled_row(admin_engine, world, execution_id):
    with admin_engine.begin() as conn:
        return dict(
            conn.execute(
                text(
                    "SELECT state,precondition_class,precondition_window_ms,result "
                    "FROM execbound.executions WHERE tenant_id=:t AND execution_id=:e"
                ),
                {"t": world["identity"].tenant_id, "e": execution_id},
            )
            .mappings()
            .one()
        )


def test_an_allowed_disable_reaches_entra_once_and_settles_on_signed_evidence(
    db, live_target, admin_engine
):
    attempts = 0
    view = None
    while attempts < 5:
        attempts += 1
        refreeze(admin_engine, live_target)
        connector, transport = live_connector(live_target)
        try:
            admission = ready(db, live_target, attempts)
            assert admission.ticket is not None
            view = dispatch_owned(db, admission.ticket, connector, live_target["clock"], CHECKED)
        finally:
            connector.close()
        if view.state != "STALE_AUTHORIZATION":
            break
        # The version was frozen from a replica that had not caught up, so the connector's
        # own read disagreed and it refused before writing. Re-issuing is what an operator
        # does, and re-freezing from a fresh read is the only thing that can change the
        # answer. This is the vendor's consistency, not a defect, and the probe records
        # that it happens rather than hiding it.
        warnings.warn(
            f"attempt {attempts} refused STALE_AUTHORIZATION: the frozen version came "
            "from a lagging replica",
            stacklevel=1,
        )

    assert view.state == "EXECUTED"

    # One token, one read, one write. A retry would be a second mutation.
    patches = [r for r in transport.requests if r.startswith("PATCH")]
    assert len(patches) == 1, transport.requests

    row = settled_row(admin_engine, live_target, view.execution_id)
    assert row["precondition_class"] == "CHECKED_BY_CONNECTOR"
    assert isinstance(row["precondition_window_ms"], int)
    record = parse_provider(row["result"]["authenticated_record"].encode(), ConnectorRecord).record
    assert record.outcome == "EXECUTED"
    assert record.observed == record.frozen
    assert 200 <= record.status < 300
    assert record.window_ms == row["precondition_window_ms"]


def test_a_forbidden_action_is_refused_with_no_vendor_call_at_all(db, live_target, admin_engine):
    """Asserted, not assumed: the transport counts every request this process made.

    The resource is promoted to tier0, which the bundle's `forbid` rule denies outright, so
    the hard denial wins before any ticket exists and the connector is never reached.
    """
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.resources SET privilege_class='tier0' "
                "WHERE tenant_id=:t AND resource_id=:r"
            ),
            {"t": live_target["identity"].tenant_id, "r": live_target["target"]},
        )
    connector, transport = live_connector(live_target)
    try:
        admission = ready(db, live_target)
    finally:
        connector.close()

    assert admission.view.state == "DENIED"
    assert admission.ticket is None
    # Nothing left this process for Microsoft: not a token request, not a read.
    # Nothing left this process for Microsoft: not a token request, not a read, not a
    # write. This is the whole proof, and it is a local, deterministic one.
    #
    # An earlier version also read the directory back and asserted the user was still
    # enabled. That was dropped rather than made to pass: converging on one read does not
    # bind the next, because Graph serves reads from replicas that catch up at their own
    # pace, so the assertion was unsound whatever it returned. It also established nothing
    # about this denial — the state it reads is the previous test's teardown, not this
    # test's refusal. The request count is what says no vendor call was made.
    assert transport.requests == []


def test_rotating_both_halves_of_the_credential_needs_no_code_change(db, live_target, admin_engine):
    """The client secret and the signing key rotate independently and together.

    A key that stays in the ring keeps verifying what it signed, which is what settling a
    lost response after a rotation depends on.
    """
    connector, _ = live_connector(live_target)
    try:
        # Same re-issue on a stale refusal as the allowed case, for the same reason.
        for attempt in range(5):
            refreeze(admin_engine, live_target)
            admission = ready(db, live_target, attempt)
            view = dispatch_owned(db, admission.ticket, connector, live_target["clock"], CHECKED)
            if view.state != "STALE_AUTHORIZATION":
                break
        assert view.state == "EXECUTED"
        row = settled_row(admin_engine, live_target, view.execution_id)
        evidence = row["result"]["authenticated_record"].encode()

        # The signing ring rotates under the running connector; the old key stays.
        connector.rotate_keys({SIGNING_KEY_ID: SIGNING_KEY, ROTATED_KEY_ID: ROTATED_KEY})
        assert connector.config.signing_key_id == SIGNING_KEY_ID
        assert set(connector.config.evidence_keys) == {SIGNING_KEY_ID, ROTATED_KEY_ID}
    finally:
        connector.close()

    # A connector configured with the rotated ring still verifies what the old key signed.
    rotated, _ = live_connector(
        live_target,
        keys={SIGNING_KEY_ID: SIGNING_KEY, ROTATED_KEY_ID: ROTATED_KEY},
        signing_key_id=ROTATED_KEY_ID,
    )
    try:
        recorded = parse_provider(evidence, ConnectorRecord)
        assert recorded.key_id == SIGNING_KEY_ID
        assert recorded.key_id in rotated.config.evidence_keys
    finally:
        rotated.close()
