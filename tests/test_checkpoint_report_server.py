# SPDX-License-Identifier: AGPL-3.0-only
"""The server settles every checkpoint report vector as the vector says (#37).

`protocol/executor/v1/vectors/checkpoint-report-v1.json` states, for every row of section 2.8 of
the executor protocol, a grant, a scenario, the report sent for it and what it settles, and it
states reports section 2.9 refuses with their codes. A vector is evidence only if the server
agrees with it, so each one is sent here through the real outcome route, over HTTP, on real
PostgreSQL, to a grant the real gateway issued.

The report cannot be the file's own bytes: a signed report binds its grant's operation, account
and hashes, and the gateway mints those. So the vectors' own executor, `checkpoint_vectors`,
writes each vector's report again for the grant the gateway answered with, from the same
scenario. It signs with keys generated for this run rather than the published test keys,
because ExecBound refuses those wherever a key is registered or configured
(`tests/test_published_test_keys.py`); the gateway is given these keys' public halves and
journal key exactly as an administrator would give them, under the vectors' own key ids. What
the file holds and what is sent here are the same function's output for two grants and two key
sets, and the conformance module accepts both, each against its own ring.

Each vector is then held three ways: the state, tier, impact and claim the server retained must
equal the vector's settlement, and must equal what the protocol package's `settlement`, section
2.8 as a pure function, says for the report; and the HTTP answer must carry the state. Each
refusal must be answered with its code, leave the grant exactly as it was, be refused by the
conformance module at a check of that code, and leave the grant able to settle.
"""

import dataclasses
import json
from contextlib import ExitStack
from datetime import timedelta

import pytest
from checkpoint_fixtures import gate_world as gate_world
from checkpoint_fixtures import grant_row, retained
from checkpoint_fixtures import owner as owner
from checkpoint_vectors import (
    BY_NAME,
    FAULTS_BY_NAME,
    Keys,
    body,
    instant,
    published,
    reported_at,
    stored_attestation,
)
from execbound_protocol.checkpoint_conformance import (
    CHECKS,
    Grant,
    Nonconformance,
    check,
    read_report,
    refused,
    settlement,
)
from execbound_protocol.report import MAX_REPORT_BYTES, OutcomeReport
from fastapi.testclient import TestClient
from test_checkpoint import console, settle_from_console
from test_execution import provision_credential, targets
from test_execution import registry as registry
from test_execution import world as world

from execbound import administration
from execbound.app import create_app
from execbound.execution import store
from execbound.execution.models import NO_PRECONDITIONS, PreconditionConfig
from execbound.provider.checkpoint_evidence import CheckpointProvider
from execbound.provider.models import ProviderCommand, provider_command
from execbound.runtime import Runtime

VECTORS = published()
VECTOR_NAMES = [vector.name for vector in VECTORS.vectors]
REFUSAL_NAMES = [refusal.name for refusal in VECTORS.refusals]
# This run's keys, which nobody else holds, and the rings the conformance module checks their
# reports against.
KEYS = Keys.generate()
RING = KEYS.ring()
JOURNAL_KEYS = KEYS.journal_keys()
# The binding every grant here is for, and what the deployment declares for it: nothing, for
# the UNAVAILABLE grants a vector names, and otherwise the class the vector's grant carries.
CONTAIN = ("mock_crowdstrike", "contain")
DECLARED = {
    "UNAVAILABLE": NO_PRECONDITIONS,
    "ASSERTED_BY_EXECUTOR": PreconditionConfig({CONTAIN: "ASSERTED_BY_EXECUTOR"}),
    "ENFORCED_BY_PROVIDER": PreconditionConfig({CONTAIN: "ENFORCED_BY_PROVIDER"}),
}
# How the server names what an impact row holds, in the specification's words.
IMPACT = {"CONFIRMED": "CONFIRMED", "NONEXECUTION": "RELEASED", "UNRESOLVED": "CHARGED"}


class Gateway:
    """A Gate deployment's HTTP surface, with this run's keys registered and configured."""

    def __init__(self, db, world, admin_engine, client, precondition_class):
        self.db, self.world, self.admin_engine, self.client = db, world, admin_engine, client
        self.tenant = world["identity"].tenant_id
        self.precondition_class = precondition_class

    def grant(self) -> Grant:
        """One grant, asked for as an executor asks, and read as the module reads one."""
        (action,) = targets(self.admin_engine, self.world, count=1)
        answered = self.client.post("/v1/execute", json=action.model_dump(mode="json"))
        assert answered.status_code == 202, answered.text
        answer = answered.json()
        assert answer["state"] == "DISPATCH_COMMITTED"
        wire = answer["checkpoint"]["grant"]
        assert wire["precondition_class"] == self.precondition_class
        assert ("provider_command" in wire) == (self.precondition_class != "UNAVAILABLE")
        row = grant_row(self.admin_engine, self.tenant, answer["execution_id"])
        # The clock below has microseconds, so the grant's instant is inside its second.
        assert row["dispatch_attempted_at"].microsecond == 250_000
        return Grant.read(answer["execution_id"], wire, row["dispatch_attempted_at"])

    def report(self, grant: Grant, raw: bytes):
        return self.client.post(
            f"/v1/executions/{grant.execution_id}/outcome",
            content=raw,
            headers={"Content-Type": "application/json"},
        )

    def held(self, grant: Grant) -> tuple[str, str | None, str, str]:
        """What the server retained for the grant: state, tier, impact and target claim, in the
        specification's words."""
        row = retained(self.admin_engine, self.tenant, grant.execution_id)
        claim = "HELD" if row.released_at is None else "RELEASED"
        return (row.state, row.tier, IMPACT[row.impact], claim)

    def unsent_command(self, grant: Grant) -> ProviderCommand:
        """The command ExecBound would have sent for this grant, from the execution it froze:
        the one a grant under UNAVAILABLE does not carry."""
        with self.db.transaction(self.tenant) as conn:
            row = store.read(conn, self.tenant, grant.execution_id)
            return provider_command(store.command(row))

    def authenticated_record(self, grant: Grant) -> object:
        """The signed evidence the settlement stored, as the JSON it was stored as."""
        row = retained(self.admin_engine, self.tenant, grant.execution_id)
        return json.loads(row.result["authenticated_record"])


@pytest.fixture
def gateways(db, gate_world, admin_engine, owner):
    """Open a Gate deployment's HTTP surface for a precondition class; one tenant, one clock."""
    world = gate_world
    tenant = world["identity"].tenant_id
    # A grant instant with microseconds, a second after everything the world provisioned, so a
    # statement signed in the grant's own second can be dated before its exact instant.
    world["clock"].value = (world["clock"].now() + timedelta(seconds=1)).replace(
        microsecond=250_000
    )
    for key_id, (algorithm, public_key) in KEYS.public_keys().items():
        administration.register_executor_key(
            owner,
            tenant,
            key_id,
            public_key.hex(),
            world["admin"].principal_id,
            algorithm=algorithm,
            now=world["clock"].now(),
        )
    # The operator's journal key for the world's Gate account: this run's, under the vectors'
    # key id.
    provider = CheckpointProvider(tenant, world["account"], "mock_crowdstrike", JOURNAL_KEYS)
    identity = world["identity"]
    with admin_engine.begin() as conn:
        # A credential that outlives the report window, as the executor guide asks for.
        token = provision_credential(
            conn,
            identity.tenant_id,
            identity.principal_id,
            world["clock"].now(),
            timedelta(days=2),
        )
    with ExitStack() as stack:

        def open_gateway(precondition_class: str) -> Gateway:
            runtime = Runtime(
                db,
                [],
                clock=world["clock"],
                preconditions=DECLARED[precondition_class],
                checkpoint_providers=(provider,),
            )
            client = stack.enter_context(TestClient(create_app(db, runtime=runtime)))
            client.headers["Authorization"] = "Bearer " + token
            return Gateway(db, world, admin_engine, client, precondition_class)

        yield open_gateway


def test_every_row_of_the_settlement_table_has_a_vector():
    """Eight rows, every signed reason in both envelopes and as a journal, every unsigned
    reason, the unknown result, a statement signed in the grant's own second, and grants under
    the two other classes: what the server is held to below."""
    assert len(VECTOR_NAMES) == 24
    assert {vector.row for vector in VECTORS.vectors} == {
        "Signed EXECUTED",
        "Signed VERSION_MISMATCH",
        "Signed CANCELLED_NOT_EXECUTED or TARGET_NOT_FOUND",
        "A provider's journal",
        "Unsigned EXECUTED",
        "Unsigned REPORTED_FAILURE",
        "Unsigned non-execution",
        "UNKNOWN",
    }


@pytest.mark.parametrize("name", VECTOR_NAMES)
def test_the_server_settles_each_vector_as_the_vector_and_section_2_8_say(gateways, name):
    vector = next(vector for vector in VECTORS.vectors if vector.name == name)
    gateway = gateways(vector.grant.wire["precondition_class"])
    grant = gateway.grant()
    raw = body(BY_NAME[name].report(grant, KEYS))
    # The module reads this report for this grant exactly as it reads the file's for the
    # vector's own: the same executor, the same scenario, another grant.
    assert check(dataclasses.replace(vector, grant=grant), raw, RING, JOURNAL_KEYS) == CHECKS

    answered = gateway.report(grant, raw)
    assert answered.status_code == (202 if vector.settles.state == "INDETERMINATE" else 200), (
        answered.text
    )
    assert answered.json()["state"] == vector.settles.state

    report = OutcomeReport.model_validate_json(raw)
    assert gateway.held(grant) == dataclasses.astuple(vector.settles)
    assert settlement(report, verified=bool(report.signed)) == vector.settles


@pytest.mark.parametrize("name", REFUSAL_NAMES)
def test_the_server_refuses_each_refusal_vector_with_its_code(gateways, name):
    refusal = next(refusal for refusal in VECTORS.refusals if refusal.name == name)
    gateway = gateways(refusal.grant.wire["precondition_class"])
    grant = gateway.grant()
    # A journal under UNAVAILABLE is of the command the gateway froze and the grant never carried.
    raw = body(FAULTS_BY_NAME[name].report(grant, KEYS, unsent=gateway.unsent_command(grant)))
    before = gateway.held(grant)
    assert before == ("DISPATCH_COMMITTED", None, "CHARGED", "HELD")

    answered = gateway.report(grant, raw)
    assert answered.status_code == 400, answered.text
    assert answered.json()["code"] == refusal.code
    assert gateway.held(grant) == before
    found = refused(dataclasses.replace(refusal, grant=grant, report=raw), RING, JOURNAL_KEYS)
    assert (found.check, found.code) == (refusal.check, refusal.code)

    # Refused, the grant is as it was, and a report sent correctly settles it.
    settles = gateway.report(
        grant,
        body(
            {
                "report_secret": grant.report_secret,
                "outcome": "EXECUTED",
                "reason": "EXECUTED",
                "record": KEYS.record(grant, "EXECUTED", "EXECUTED"),
            }
        ),
    )
    assert settles.status_code == 200, settles.text
    assert gateway.held(grant) == ("EXECUTED", "ATTESTED", "CONFIRMED", "RELEASED")


def test_the_server_reads_a_report_of_exactly_the_bound_and_refuses_one_byte_more(gateways):
    """The body bound, which a vector cannot carry without carrying 16 KiB: the module's `body`
    check and the route agree on both sides of it."""
    gateway = gateways("ENFORCED_BY_PROVIDER")
    vector = next(vector for vector in VECTORS.vectors if vector.name == "asserted-executed")

    grant = gateway.grant()
    raw = body(BY_NAME[vector.name].report(grant, KEYS))
    over = raw[:-1] + b" " * (MAX_REPORT_BYTES + 1 - len(raw)) + b"}"
    with pytest.raises(Nonconformance) as raised:
        read_report(grant, over, RING, JOURNAL_KEYS)
    assert (raised.value.check, raised.value.code) == ("body", "INVALID_REQUEST")
    answered = gateway.report(grant, over)
    assert answered.status_code == 400, answered.text
    assert answered.json()["code"] == "INVALID_REQUEST"
    assert gateway.held(grant) == ("DISPATCH_COMMITTED", None, "CHARGED", "HELD")

    exact = raw[:-1] + b" " * (MAX_REPORT_BYTES - len(raw)) + b"}"
    assert len(exact) == MAX_REPORT_BYTES
    assert check(dataclasses.replace(vector, grant=grant), exact, RING, JOURNAL_KEYS) == CHECKS
    answered = gateway.report(grant, exact)
    assert answered.status_code == 200, answered.text
    assert gateway.held(grant) == dataclasses.astuple(vector.settles)


# ES256 arrives on the route only as an attestation (section 2.6). The form a settlement stores
# an attestation in is ES256 too, and an administrator's settlement may present it again, which
# is why the verifier both paths share still reads it; the route refuses that form in a `record`
# before the verifier sees it, because a `record` is an Ed25519 signed outcome.


def _statement(grant: Grant, outcome: str = "EXECUTED", reason: str = "EXECUTED") -> dict:
    return {"report_secret": grant.report_secret, "outcome": outcome, "reason": reason}


def test_the_route_takes_es256_only_as_an_attestation_and_never_in_its_stored_form(gateways):
    """The stored form presented as a record is refused and settles nothing; the same statement
    sent as the attestation it is settles, and is stored as exactly the form refused above."""
    gateway = gateways("ENFORCED_BY_PROVIDER")
    grant = gateway.grant()
    token = KEYS.attestation(grant, "EXECUTED", "EXECUTED")
    stored = stored_attestation(token)
    before = gateway.held(grant)
    assert before == ("DISPATCH_COMMITTED", None, "CHARGED", "HELD")

    refused = gateway.report(grant, body(_statement(grant) | {"record": stored}))
    assert refused.status_code == 400, refused.text
    assert refused.json()["code"] == "INVALID_RECORD"
    assert gateway.held(grant) == before

    settled = gateway.report(grant, body(_statement(grant) | {"attestation": token}))
    assert settled.status_code == 200, settled.text
    assert gateway.held(grant) == ("EXECUTED", "ATTESTED", "CONFIRMED", "RELEASED")
    assert gateway.authenticated_record(grant) == stored


@pytest.mark.parametrize("correction", [False, True], ids=["an unsettled grant", "the correction"])
def test_the_administrators_settlement_still_takes_the_stored_form(
    db, gate_world, admin_engine, gateways, correction
):
    """The administrator's settlement and its correction (docs/CHECKPOINT.md, What a settled
    row is closed to) take the stored form the route refuses, through the console.

    An unsettled grant is first sent the stored form as a record, which the route refuses and
    which leaves the grant as it was; the administrator then settles it from those same bytes.
    The correction is the one settled row the administrator may move: the executor's unsigned
    word that its call failed, corrected by a signed non-execution in its stored form.
    """
    gateway = gateways("ENFORCED_BY_PROVIDER")
    grant = gateway.grant()
    signed = ("FAILED_NOT_EXECUTED", "CANCELLED_NOT_EXECUTED") if correction else ("EXECUTED",) * 2
    stored = stored_attestation(KEYS.attestation(grant, *signed))
    if correction:
        failure = _statement(grant, "FAILED_EFFECT_UNKNOWN", "REPORTED_FAILURE")
        failure["reported_at"] = instant(reported_at(grant))
        assert gateway.report(grant, body(failure)).status_code == 200
        assert gateway.held(grant) == ("FAILED_EFFECT_UNKNOWN", "ASSERTED", "CONFIRMED", "HELD")
    else:
        before = gateway.held(grant)
        refused = gateway.report(grant, body(_statement(grant) | {"record": stored}))
        assert refused.status_code == 400, refused.text
        assert refused.json()["code"] == "INVALID_RECORD"
        assert gateway.held(grant) == before

    with console(
        db, gate_world, admin_engine, preconditions=DECLARED["ENFORCED_BY_PROVIDER"]
    ) as admin:
        settled = settle_from_console(
            admin,
            grant.execution_id,
            reason="settled from the attestation as it is stored",
            record=json.dumps(stored),
        )
        assert settled.status_code == 200, settled.text
    if correction:
        assert gateway.held(grant) == ("FAILED_NOT_EXECUTED", "ATTESTED", "RELEASED", "RELEASED")
    else:
        assert gateway.held(grant) == ("EXECUTED", "ATTESTED", "CONFIRMED", "RELEASED")
    assert gateway.authenticated_record(grant) == stored
