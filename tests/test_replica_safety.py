# SPDX-License-Identifier: AGPL-3.0-only
"""Two gateways against one database: the guarantee the high-availability guide rests on.

#411 says a Community installation may
run several gateways behind a load balancer, and that the guide is published only once this
passes, because nobody had shown that replicas cannot overspend a limit or consume an approval
twice. The shared state is supposed to be in PostgreSQL and every fence with it; these tests
are what says so.

**What a replica is here.** Each guarantee is checked twice. The first pair runs two
`Database`s in this process, each a separate engine with its own connection pool, through the
kernel's admission path: that is what two replicas are from the database's point of view, and
it is where every fence in the kernel lives. The second pair runs two gateway processes, each
the image's application under uvicorn reading one private configuration file
(`gateway_process`), and drives them over HTTP the way agents and approvers do: an agent's
bearer credential on `/v1/execute`, a person's session on the console API. A defect that kept
a count or a claim in a module global would be shared by the first pair's two runtimes and
caught only by the second, where each process holds its own.

**Three more paths, across processes only.** The MCP adapter's `execute` against the same
ceiling, with the older protocol revision's handshake made on the process its call does not
reach; a person's console session signed in on one process, used on the other and ended from
each; and two `execbound recover` processes settling one uncertain operation. Each already has
an in-process counterpart (`test_mcp_surface`, `test_console_api_settings`, RC7 in
`test_recovery_run`), and each process case here was shown to fail under a planted
per-process defect that its counterpart passes, applied locally and never committed.

What none of this is: a deployment. Every process runs on one host against one PostgreSQL,
with no load balancer between them and the test. The Arcade hooks are not checked across
processes, because the gateway fixture's configuration carries no `arcade` block.
`docs/DEPLOYMENT.md` says so in those words rather than claiming more than this run
establishes.
"""

import json
import os
import secrets
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from urllib.parse import urlsplit

import pytest
from conftest import local_test_url, remember_secret
from console_api_fixtures import API, ORIGIN, ConsoleClient, sign_in
from demo_world import provision_mock
from gateway_process import GatewayProcess, write_configuration
from scope_fixtures import rule, scoped_bundle
from sqlalchemy import text
from test_execution import activate, counts, request, targets
from test_execution import registry as registry
from test_execution import world as world
from test_human_surface import credential
from test_protected_path import live_provider as live_provider
from test_recovery_run import lost_response, state_of

from execbound.db import Database
from execbound.execution import admit, decide_approval
from execbound.policy.models import ContextSetting

pytestmark = pytest.mark.integration


@pytest.fixture
def replica(db):
    """A second gateway: its own engine and pool, the same database, the same tenant."""
    other = Database(local_test_url(os.environ["TEST_DATABASE_URL"], "execbound_app"), pool_size=1)
    yield other
    other.close()


def test_two_gateways_admit_exactly_the_limit_at_its_threshold(db, replica, world, admin_engine):
    """Six requests at once over two gateways, a ceiling of three: three pass.

    The ceiling is a hard one, so the three that do not pass are refused rather than
    escalated, and the count of retained impact rows is the check that nothing was reserved
    and lost. A replica that counted its own admissions rather than the tenant's would admit
    three each.
    """
    scoped_bundle(db, world, rule(max_targets=3, on_exceed="DENY"))
    requests = targets(admin_engine, world, 6)
    gateways = (db, replica)
    barrier = Barrier(6)

    def submit(index):
        barrier.wait(timeout=10)
        return admit(gateways[index % 2], world["identity"], requests[index], world["clock"])

    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(submit, range(6)))
    admitted = [item for item in results if item.ticket is not None]
    denied = [item for item in results if item.view.state == "DENIED"]
    assert len(admitted) == 3, [item.view.state for item in results]
    assert len(denied) == 3
    assert counts(admin_engine, world["identity"].tenant_id)["execution_impact"] == 3


def test_one_approval_is_consumed_once_across_two_gateways(db, replica, world, admin_engine):
    """An approval granted on one gateway is spent once, whichever gateway spends it.

    Six retries at once, three on each, of an execution a person has approved. Exactly one
    dispatch ticket exists afterwards and exactly one impact row was charged: the second
    gateway can see the approval and cannot take it a second time.
    """
    first = admit(db, world["identity"], request(world), world["clock"])
    assert first.view.state == "PENDING_APPROVAL"
    decide_approval(db, world["human"], first.view.approval_id, "APPROVE", world["clock"])
    gateways = (db, replica)
    barrier = Barrier(6)

    def submit(index):
        barrier.wait(timeout=10)
        return admit(
            gateways[index % 2],
            world["identity"],
            request(world, idempotency_key=f"replica-{index}"),
            world["clock"],
        )

    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(submit, range(6)))
    assert sum(item.ticket is not None for item in results) == 1
    assert len({item.view.execution_id for item in results}) == 1
    tenant = world["identity"].tenant_id
    assert counts(admin_engine, tenant)["execution_impact"] == 1
    assert counts(admin_engine, tenant)["approvals"] == 1


# Over HTTP, between two processes.
#
# The same two guarantees, each process the application the image runs, reached the way an
# agent and an approver reach a deployment. The processes take seconds to start where the
# runtimes above take none, so the world's facts are given an hour rather than the contract's
# five minutes: what is under test is the fences, and a fact that went stale while a loaded
# runner started two gateways would refuse every request for a reason that is not one of them.

LONG_FACTS = tuple(
    ContextSetting(
        context_contract_version="endpoint-isolation.v1",
        source_kind=kind,
        max_age_seconds=3600,
        permitted_writers=(writer,),
    )
    for kind, writer in (("inventory", "inventory_sync"), ("incident", "soc_analyst"))
)


@pytest.fixture
def gateways(tmp_path, live_provider, seeded):
    """Two gateway processes reading one private configuration, against this worker's database.

    The configuration names the protected mock as the tenant's connector, so an admitted
    request is dispatched to a real provider process too, and its origin is the one the
    console fixtures sign in at, so a person's session works on either process.
    """
    key = remember_secret(secrets.token_hex(32))
    configuration = write_configuration(
        tmp_path / "gateway.json", ORIGIN, key, [live_provider.config]
    )
    runtime_role = local_test_url(os.environ["TEST_DATABASE_URL"], "execbound_app")
    processes = [
        GatewayProcess(
            name,
            runtime_role.render_as_string(hide_password=False),
            configuration,
            urlsplit(ORIGIN).netloc,
            tmp_path,
        )
        for name in ("first", "second")
    ]
    try:
        for process in processes:
            process.launch()
        for process in processes:
            process.wait()
        yield tuple(processes)
    finally:
        for process in processes:
            process.stop()


def concurrently(gateways, token, bodies):
    """Every body at once, each from a client of its own, alternately on the two processes.

    Each client opens its connection before the barrier, so what races is the requests and
    not the connection setup.
    """
    clients = [gateways[index % 2].client(token) for index in range(len(bodies))]
    try:
        for client in clients:
            assert client.get("/health/ready").status_code == 200
        barrier = Barrier(len(bodies))

        def submit(index):
            barrier.wait(timeout=30)
            return clients[index].post("/v1/execute", json=bodies[index])

        with ThreadPoolExecutor(max_workers=len(bodies)) as pool:
            return list(pool.map(submit, range(len(bodies))))
    finally:
        for client in clients:
            client.close()


def tickets(engine, tenant):
    """Dispatch tickets issued: admission issues each with the transition to DISPATCH_COMMITTED."""
    with engine.connect() as conn:
        return conn.execute(
            text(
                "SELECT count(*) FROM execbound.execution_events "
                "WHERE tenant_id=:t AND to_state='DISPATCH_COMMITTED'"
            ),
            {"t": tenant},
        ).scalar_one()


def invocations(live_provider):
    """Dispatches the protected mock received, from its own journal of them."""
    journal = live_provider.environment["TEST_PROVIDER_INVOCATIONS"]
    if not os.path.exists(journal):
        return 0
    with open(journal, encoding="utf-8") as lines:
        return len(lines.read().split())


def test_two_gateway_processes_admit_exactly_the_limit_at_its_threshold(
    db, world, admin_engine, live_provider, gateways, seeded
):
    """Six agent requests at once over two gateway processes, a ceiling of three: three pass.

    The other three are answered DENIED with the limit as their category, and the retained
    impact rows, the tickets and the provider's own count of dispatches all say three: nothing
    was reserved and lost, and nothing was sent that admission did not admit. A process that
    counted its own admissions rather than the tenant's would admit three on each.
    """
    activate(db, world, context_settings=LONG_FACTS)
    scoped_bundle(db, world, rule(max_targets=3, on_exceed="DENY"))
    requests = targets(admin_engine, world, 6)
    provision_mock(live_provider, admin_engine, world)
    responses = concurrently(
        gateways, seeded["tokens"][0], [item.model_dump(mode="json") for item in requests]
    )
    answers = [response.json() for response in responses]
    assert [response.status_code for response in responses] == [200] * 6, answers
    states = sorted(answer["state"] for answer in answers)
    assert states == ["DENIED"] * 3 + ["EXECUTED"] * 3, states
    assert {answer["denial"] for answer in answers if answer["state"] == "DENIED"} == {"limit"}
    tenant = world["identity"].tenant_id
    assert counts(admin_engine, tenant)["execution_impact"] == 3
    assert tickets(admin_engine, tenant) == 3
    assert invocations(live_provider) == 3


def test_one_approval_is_consumed_once_across_two_gateway_processes(
    db, world, admin_engine, live_provider, gateways, seeded
):
    """An approval decided on one process is spent once, whichever process spends it.

    The agent asks on the first process, a person approves through the second's console API,
    and six retries at once, three on each process, each under a key of its own, all answer
    the one execution: 200 once it has executed, 202 while its dispatch is committed. Exactly
    one ticket was issued, one impact row charged and one dispatch received by the provider:
    the process that did not issue the ticket saw the approval already taken and could not
    take it a second time.

    The answers are checked first, statuses before bodies, because they are where a claim kept
    in one process's memory shows: the database still refuses the other process that claim,
    so every count below stays at one and only that process's answers, refusals, say so.
    """
    activate(db, world, context_settings=LONG_FACTS)
    first, second = gateways
    token = seeded["tokens"][0]
    with first.client(token) as agent:
        asked = agent.post("/v1/execute", json=request(world).model_dump(mode="json"))
    assert asked.status_code == 202, asked.text
    pending = asked.json()
    assert pending["state"] == "PENDING_APPROVAL"
    approval_id = pending["approval_id"]
    with second.client() as browser:
        approver = sign_in(browser, admin_engine, world["human"])
        continuation = approver.get(f"{API}/approvals/{approval_id}").json()["continuation"]
        decided = approver.post(
            f"{API}/approvals/{approval_id}/decision",
            {"decision": "APPROVE", "comment": "", "continuation": continuation},
        )
    assert decided.status_code == 200, decided.text
    assert decided.json()["approval_state"] == "APPROVED"
    responses = concurrently(
        gateways,
        token,
        [
            request(world, idempotency_key=f"replica-{index}").model_dump(mode="json")
            for index in range(6)
        ],
    )
    # Every status before any body is read: a refusal carries no execution id, and a retry
    # answered 409 or 503 must fail here with all six answers, not as a missing key.
    replies = [(response.status_code, response.text) for response in responses]
    assert {status for status, _ in replies} <= {200, 202}, replies
    answers = [response.json() for response in responses]
    assert {answer["execution_id"] for answer in answers} == {pending["execution_id"]}, replies
    assert {
        (response.status_code, answer["state"])
        for response, answer in zip(responses, answers, strict=True)
    } <= {(200, "EXECUTED"), (202, "DISPATCH_COMMITTED")}, replies
    tenant = world["identity"].tenant_id
    assert tickets(admin_engine, tenant) == 1
    assert counts(admin_engine, tenant)["execution_impact"] == 1
    assert counts(admin_engine, tenant)["approvals"] == 1
    assert invocations(live_provider) == 1
    assert live_provider.store.resource(tenant, world["canonical"]).mutation_count == 1


# The MCP adapter, between two processes.
#
# The adapter is a second door into the same kernel, so the ceiling it must keep is the one
# above. What it adds is a protocol with a connection of its own: the older revision opens
# with a handshake, and a server that kept the session that handshake makes in memory would
# not know it on the process that receives the client's next request. The gateway serves
# the adapter stateless, and these calls are made the way a client behind a balancer with
# no session affinity makes them.

CURRENT_REVISION = "2026-07-28"
OLDER_REVISION = "2025-11-25"
STREAMS = "application/json, text/event-stream"


def mcp_caller(opening, calling, token, revision):
    """An MCP client calling on `calling`, opened on `opening`, and the headers it calls with.

    The current revision has no handshake: each request states its revision and its
    capabilities, so there is nothing to open. The older one sends `initialize` and then
    `notifications/initialized`, both here on `opening`, and from then on carries whatever
    session id the server answered with, as a client must. A stateless server answers none.
    The calling client sends one request before it is returned, so what races later is the
    calls and not the connection setup.
    """
    headers = {"Accept": STREAMS, "MCP-Protocol-Version": revision}
    if revision == CURRENT_REVISION:
        headers.update({"MCP-Method": "tools/call", "MCP-Name": "execute"})
    else:
        with opening.client(token) as opener:
            opened = opener.post(
                "/mcp/",
                json={
                    "jsonrpc": "2.0",
                    "id": "open",
                    "method": "initialize",
                    "params": {
                        "protocolVersion": OLDER_REVISION,
                        "capabilities": {},
                        "clientInfo": {"name": "replica-safety", "version": "1"},
                    },
                },
                headers={"Accept": STREAMS},
            )
            assert opened.status_code == 200, opened.text
            assert opened.json()["result"]["protocolVersion"] == OLDER_REVISION
            session = opened.headers.get("mcp-session-id")
            if session is not None:
                headers["Mcp-Session-Id"] = session
            ready = opener.post(
                "/mcp/",
                json={"jsonrpc": "2.0", "method": "notifications/initialized"},
                headers=headers,
            )
            assert ready.status_code == 202, ready.text
    client = calling.client(token)
    assert client.get("/health/ready").status_code == 200
    return client, headers


def mcp_execute(client, headers, revision, index, body):
    """One `tools/call` of `execute`, carrying the request the HTTP surface would take."""
    params = {"name": "execute", "arguments": {"request": body}}
    if revision == CURRENT_REVISION:
        params["_meta"] = {
            "io.modelcontextprotocol/protocolVersion": CURRENT_REVISION,
            "io.modelcontextprotocol/clientCapabilities": {},
        }
    return client.post(
        "/mcp/",
        json={"jsonrpc": "2.0", "id": index, "method": "tools/call", "params": params},
        headers=headers,
    )


def test_mcp_calls_on_two_gateway_processes_admit_exactly_the_limit_at_its_threshold(
    db, world, admin_engine, live_provider, gateways, seeded
):
    """Six MCP `execute` calls at once over two gateway processes, a ceiling of three.

    Three on each process; the first three clients speak the current revision and the last
    three the older one, each of those opened on the process it does not call on, so each
    process answers both revisions and every older-revision call arrives where its handshake
    did not. Every call is answered, three `EXECUTED` and three `DENIED` with the limit as
    their category, and the impact rows, the tickets and the provider's own count of
    dispatches all say three, exactly as for six requests over `/v1/execute`.
    """
    activate(db, world, context_settings=LONG_FACTS)
    scoped_bundle(db, world, rule(max_targets=3, on_exceed="DENY"))
    requests = targets(admin_engine, world, 6)
    provision_mock(live_provider, admin_engine, world)
    token = seeded["tokens"][0]
    revisions = [CURRENT_REVISION] * 3 + [OLDER_REVISION] * 3
    callers = []
    try:
        for index, revision in enumerate(revisions):
            calling, opening = gateways[index % 2], gateways[(index + 1) % 2]
            callers.append(mcp_caller(opening, calling, token, revision))
        barrier = Barrier(len(callers))

        def submit(index):
            client, headers = callers[index]
            body = requests[index].model_dump(mode="json")
            barrier.wait(timeout=30)
            return mcp_execute(client, headers, revisions[index], index, body)

        with ThreadPoolExecutor(max_workers=len(callers)) as pool:
            responses = list(pool.map(submit, range(len(callers))))
    finally:
        for client, _ in callers:
            client.close()
    # Every status before any body, so a call refused at the transport fails here with all
    # six answers rather than as a missing key.
    replies = [(response.status_code, response.text) for response in responses]
    assert {status for status, _ in replies} == {200}, replies
    results = [response.json()["result"] for response in responses]
    assert not any(result["isError"] for result in results), replies
    answers = [result["structuredContent"] for result in results]
    states = sorted(answer["state"] for answer in answers)
    assert states == ["DENIED"] * 3 + ["EXECUTED"] * 3, replies
    assert {answer["denial"] for answer in answers if answer["state"] == "DENIED"} == {"limit"}
    tenant = world["identity"].tenant_id
    assert counts(admin_engine, tenant)["execution_impact"] == 3
    assert tickets(admin_engine, tenant) == 3
    assert invocations(live_provider) == 3


# A console session, between two processes.
#
# A person's session is a row, and every request rereads it under the tenant fence, so a
# session opened on one process is good on another and ends on both the moment it ends on
# either. A process that remembered a session it had already read would keep answering it
# after another process ended it.


def carried(session, client):
    """The same session on another process's client: its cookies copied, its token kept.

    Copied rather than shared, so a sign-out answer that clears the cookies on one client
    leaves the other holding them, and what refuses that client afterwards is the server.
    """
    for cookie in session.client.cookies.jar:
        client.cookies.jar.set_cookie(cookie)
    return ConsoleClient(client, session.csrf)


def signed_out(holder):
    """The session's next request is refused as one that is no longer signed in.

    Compared as a status and a code, so a session still answered fails without printing
    the session it was answered with.
    """
    answer = holder.get(API + "/session")
    assert (answer.status_code, answer.json().get("code")) == (401, "SESSION_REQUIRED")


def test_a_console_session_moves_between_gateway_processes_and_ends_on_both(
    world, admin_engine, gateways
):
    """One person, two sessions, each signed in on one process and used on the other.

    Each session reads on the process it did not sign in on. Then the second session ends
    the person's other sessions from the first process, and the first session is refused on
    the second process at its next request; and the second session signs out on the second
    process, and is refused on the first at its next request. Each revocation is felt on
    the process that did not make it, with no wait between them.
    """
    first, second = gateways
    principal = str(world["human"].principal_id)
    with (
        first.client() as one_here,
        second.client() as one_there,
        second.client() as two_here,
        first.client() as two_there,
    ):
        one = sign_in(one_here, admin_engine, world["human"])
        moved_one = carried(one, one_there)
        read = moved_one.get(API + "/session")
        assert read.status_code == 200, read.text
        assert read.json()["identity"]["principal_id"] == principal
        two = sign_in(two_here, admin_engine, world["human"])
        moved_two = carried(two, two_there)
        settings = moved_two.get(API + "/settings")
        assert settings.status_code == 200, settings.text
        assert settings.json()["others"] == 1
        # Revoked on the first process, felt on the second.
        ended = moved_two.post(API + "/settings/sessions/revoke-others", {})
        assert ended.status_code == 200, ended.text
        assert ended.json()["others"] == 0
        signed_out(moved_one)
        signed_out(one)
        # Signed out on the second process, felt on the first.
        out = two.client.post(
            "/session/logout", data={"csrf": two.csrf}, headers={"Origin": ORIGIN}
        )
        assert out.status_code == 303, out.text
        signed_out(moved_two)


# The recovery run, two processes at once.
#
# `execbound recover` is a process of its own wherever it runs: on the jobs service, which
# holds each interval with an advisory lock, and by hand, which holds nothing. Two runs that
# both found one uncertain operation must settle it once, and RC7 (`test_recovery_run`)
# shows that for two runs in one process. Here each run is a process.
#
# What each process runs is the command's own entry point, `execbound.cli:main`, with the
# one change RC7 makes between its threads: once a run's real read of the unsettled
# operations has returned, it waits until the other run has read too, so both hold the
# operation as unsettled before either takes the fence to settle it. Without the wait the
# first run could settle the operation before the second read it, and the second would find
# nothing to race for. The barrier is a directory both processes write their mark into,
# because the processes share nothing else; a lock in the database would not do, because
# every transaction the run opens gives up on a lock after five seconds.
RECOVER = """
import os, sys, time
from pathlib import Path

from execbound import recovery_run
from execbound.cli import main

barrier = Path(os.environ["TEST_RECOVERY_BARRIER"])
read = recovery_run.select_unsettled


def select_together(*args, **kwargs):
    rows = read(*args, **kwargs)
    (barrier / str(os.getpid())).write_text(str(len(rows)))
    deadline = time.monotonic() + 90
    while len(list(barrier.iterdir())) < 2:
        if time.monotonic() > deadline:
            raise SystemExit("The other recovery run never read the unsettled operations")
        time.sleep(0.02)
    return rows


recovery_run.select_unsettled = select_together
sys.argv = ["execbound", *sys.argv[1:]]
main()
"""


def test_two_recovery_processes_settle_one_uncertain_operation_once(
    db, world, admin_engine, live_provider, tmp_path
):
    """Two `execbound recover` processes find one INDETERMINATE operation; it settles once.

    The provider committed the effect and its answer was lost. Both runs examine the
    operation and both report it executed, the second because it finds the first's
    settlement under the fence; neither leaves it unresolved. The execution moved to
    `EXECUTED` once, in its own history and in the audit chain, the impact is one row, and
    the provider holds one mutation from the one dispatch it ever received: recovery reads
    its journal and sends nothing.
    """
    tenant = world["identity"].tenant_id
    winner = lost_response(db, world, live_provider)
    execution = str(winner.view.execution_id)
    # Older than the command's grace period by the system clock both processes read.
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.executions SET changed_at = changed_at - interval '10 minutes' "
                "WHERE execution_id=:e"
            ),
            {"e": execution},
        )
    configuration = write_configuration(
        tmp_path / "recover.json",
        ORIGIN,
        remember_secret(secrets.token_hex(32)),
        [live_provider.config],
    )
    token_file = tmp_path / "admin.token"
    token_file.write_text(credential(admin_engine, world["admin"]), encoding="ascii")
    barrier = tmp_path / "read"
    barrier.mkdir()
    environment = {
        **os.environ,
        "DATABASE_URL": local_test_url(
            os.environ["TEST_DATABASE_URL"], "execbound_app"
        ).render_as_string(hide_password=False),
        "EXECBOUND_RUNTIME_CONFIG": str(configuration),
        "TEST_RECOVERY_BARRIER": str(barrier),
    }
    environment.pop("EXECBOUND_RUNTIME_CONFIG_JSON", None)
    command = [
        sys.executable,
        "-c",
        RECOVER,
        "recover",
        "--tenant",
        str(tenant),
        "--credential-file",
        str(token_file),
    ]
    runs = []
    try:
        for _ in range(2):
            runs.append(
                subprocess.Popen(
                    command,
                    env=environment,
                    # Away from the checkout, so no `.env` file there is read.
                    cwd=tmp_path,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                )
            )
        finished = [run.communicate(timeout=180) for run in runs]
    finally:
        for run in runs:
            if run.poll() is None:
                run.kill()
                run.wait(timeout=10)
    assert [run.returncode for run in runs] == [0, 0], [errors for _, errors in finished]
    # Both runs read the operation as unsettled before either settled it.
    assert sorted(mark.read_text() for mark in barrier.iterdir()) == ["1", "1"]
    reports = [json.loads(output) for output, _ in finished]
    assert [
        (report["examined"], report["executed"], report["unresolved"]) for report in reports
    ] == [(1, 1, 0), (1, 1, 0)], reports
    assert state_of(admin_engine, winner.view.execution_id) == "EXECUTED"
    with admin_engine.connect() as conn:
        moved = conn.execute(
            text(
                "SELECT count(*) FROM execbound.execution_events "
                "WHERE tenant_id=:t AND execution_id=:e AND to_state='EXECUTED'"
            ),
            {"t": tenant, "e": execution},
        ).scalar_one()
        audited = conn.execute(
            text(
                "SELECT count(*) FROM execbound.audit_events WHERE tenant_id=:t "
                "AND kind='execution.transition' AND payload->>'to_state'='EXECUTED' "
                "AND payload->>'execution_id'=:e"
            ),
            {"t": tenant, "e": execution},
        ).scalar_one()
    assert (moved, audited) == (1, 1)
    assert counts(admin_engine, tenant)["execution_impact"] == 1
    assert invocations(live_provider) == 1
    assert live_provider.store.resource(tenant, world["canonical"]).mutation_count == 1
