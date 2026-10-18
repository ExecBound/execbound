# SPDX-License-Identifier: AGPL-3.0-only
"""A provider's journal settles a checkpoint only under a grant that carried its command (#37).

Section 2.6 of the executor protocol makes a journal the provider's signed record of exactly the
grant's `provider_command`, and sections 2.2 and 2.5 give a grant under `UNAVAILABLE` none. So the
outcome route refuses a journal under such a grant as `INVALID_RECORD` and leaves the grant as it
was. Which class a grant was issued under is the one admission recorded on the execution at the
first answer, in `executions.precondition_class`. A later answer to a retry describes the grant
under that recorded class and records nothing, so a redeployment that changes the declaration
changes neither what a retry is told nor what the route weighs for a grant already issued.

A grant issued by an earlier release recorded no class, and an empty class cannot tell an
`ENFORCED_BY_PROVIDER` grant from an `UNAVAILABLE` one, so a journal under it is accepted as it
always was. Such a grant stays reportable only within a report window, a day at most, of the
last grant an earlier release issued. The refusal is the route's: the administrator's settlement
weighs a journal as it always did.

Every report here is sent over HTTP to the real outcome route on real PostgreSQL, for a grant
the real gateway issued, with the journal key a deployment configures for the Gate account. The
rows these hold are TG1 and TG3 in `docs/ACCEPTANCE_TESTS.md`.
"""

import json
from contextlib import ExitStack
from datetime import timedelta
from uuid import UUID

import pytest
from checkpoint_fixtures import (
    gate_journal,
    gate_runtime,
    journal_provider,
    report_body,
    retained,
    scoped,
    signed_record,
)
from checkpoint_fixtures import gate_world as gate_world
from checkpoint_fixtures import owner as owner
from fastapi.testclient import TestClient
from sqlalchemy import text
from test_checkpoint import article, console, settle_from_console
from test_execution import provision_credential, targets
from test_execution import registry as registry
from test_execution import world as world

from execbound.app import create_app
from execbound.execution.models import NO_PRECONDITIONS, PreconditionConfig

CONTAIN = ("mock_crowdstrike", "contain")
DECLARED = {
    "UNAVAILABLE": NO_PRECONDITIONS,
    "ASSERTED_BY_EXECUTOR": PreconditionConfig({CONTAIN: "ASSERTED_BY_EXECUTOR"}),
    "ENFORCED_BY_PROVIDER": PreconditionConfig({CONTAIN: "ENFORCED_BY_PROVIDER"}),
}
# A deployment may also be redeployed to declare the class no grant is issued under; a grant
# issued before keeps its own.
REDEPLOYED = {
    **DECLARED,
    "CHECKED_BY_CONNECTOR": PreconditionConfig({CONTAIN: "CHECKED_BY_CONNECTOR"}),
}
# How the server names what an impact row holds, in the specification's words.
IMPACT = {"CONFIRMED": "CONFIRMED", "NONEXECUTION": "RELEASED", "UNRESOLVED": "CHARGED"}
GRANTED = ("DISPATCH_COMMITTED", None, "CHARGED", "HELD")
PROVIDER_VERIFIED = ("EXECUTED", "PROVIDER_VERIFIED", "CONFIRMED", "RELEASED")


@pytest.fixture
def deployments(db, gate_world, admin_engine):
    """Open the HTTP surface of a Gate deployment that declares one class for the binding.

    Every deployment shares the tenant, the clock, the executor's credential and the journal
    key configured for the Gate account, so a grant one of them issued can be retried or
    reported through another, as it can across a redeployment.
    """
    world = gate_world
    identity = world["identity"]
    with admin_engine.begin() as conn:
        # A credential that outlives the report window, as the executor guide asks for.
        token = provision_credential(
            conn, identity.tenant_id, identity.principal_id, world["clock"].now(), timedelta(days=2)
        )
    with ExitStack() as stack:

        def open_deployment(declared: str) -> TestClient:
            runtime = gate_runtime(
                db,
                world,
                preconditions=REDEPLOYED[declared],
                checkpoint_providers=(journal_provider(world),),
            )
            client = stack.enter_context(TestClient(create_app(db, runtime=runtime)))
            client.headers["Authorization"] = "Bearer " + token
            return client

        yield open_deployment


def ask(client: TestClient, action) -> dict:
    """The answer to one checkpoint request: a grant, the first time or again."""
    answered = client.post("/v1/execute", json=action.model_dump(mode="json"))
    assert answered.status_code == 202, answered.text
    answer = answered.json()
    assert answer["state"] == "DISPATCH_COMMITTED"
    return answer


def send(client: TestClient, execution_id: str, report: dict):
    return client.post(
        f"/v1/executions/{execution_id}/outcome",
        content=json.dumps(report).encode(),
        headers={"Content-Type": "application/json"},
    )


def held(admin_engine, world, execution_id) -> tuple[str, str | None, str, str]:
    """What the server retained: state, tier, impact and target claim, in the spec's words."""
    row = retained(admin_engine, world["identity"].tenant_id, UUID(str(execution_id)))
    return (
        row.state,
        row.tier,
        IMPACT[row.impact],
        "HELD" if row.released_at is None else "RELEASED",
    )


def recorded_class(admin_engine, world, execution_id) -> str | None:
    tenant = world["identity"].tenant_id
    with admin_engine.begin() as conn:
        scoped(conn, tenant)
        return conn.execute(
            text(
                "SELECT precondition_class FROM execbound.executions "
                "WHERE tenant_id=:t AND execution_id=:e"
            ),
            {"t": tenant, "e": execution_id},
        ).scalar_one()


def forget_class(admin_engine, world, execution_id) -> None:
    """Leave the grant as one issued before the class was recorded leaves it: with none."""
    tenant = world["identity"].tenant_id
    with admin_engine.begin() as conn:
        scoped(conn, tenant)
        conn.execute(
            text(
                "UPDATE execbound.executions SET precondition_class=NULL "
                "WHERE tenant_id=:t AND execution_id=:e"
            ),
            {"t": tenant, "e": execution_id},
        )


def granted_classes(admin_engine, world, execution_id) -> list[str]:
    """The class each answer for this execution carried, as its audit event retains it."""
    tenant = world["identity"].tenant_id
    with admin_engine.begin() as conn:
        scoped(conn, tenant)
        return list(
            conn.execute(
                text(
                    "SELECT payload->>'precondition_class' FROM execbound.audit_events "
                    "WHERE tenant_id=:t AND kind='execution.checkpoint_granted' "
                    "AND payload->>'execution_id'=:e ORDER BY sequence"
                ),
                {"t": tenant, "e": str(execution_id)},
            ).scalars()
        )


@pytest.mark.parametrize("declared", list(DECLARED))
def test_a_grant_records_the_class_it_was_issued_under(
    deployments, gate_world, admin_engine, declared
):
    client = deployments(declared)
    (action,) = targets(admin_engine, gate_world, count=1)
    answer = ask(client, action)
    grant = answer["checkpoint"]["grant"]
    assert grant["precondition_class"] == declared
    # A class that is not UNAVAILABLE, ASSERTED_BY_EXECUTOR's included, carries a version and
    # the command ExecBound would have sent; UNAVAILABLE carries neither.
    assert ("provider_command" in grant) == (declared != "UNAVAILABLE")
    assert recorded_class(admin_engine, gate_world, answer["execution_id"]) == declared
    assert granted_classes(admin_engine, gate_world, answer["execution_id"]) == [declared]


def test_a_journal_under_an_unavailable_grant_is_refused_and_settles_nothing(
    db, deployments, gate_world, admin_engine
):
    """The journal binds the command ExecBound would have sent, so it verifies under the key
    the operator configured; the grant carried no command, so it is refused all the same, and a
    correct report settles the grant afterwards."""
    world = gate_world
    client = deployments("UNAVAILABLE")
    (action,) = targets(admin_engine, world, count=1)
    answer = ask(client, action)
    execution_id = answer["execution_id"]
    secret = answer["checkpoint"]["grant"]["report_secret"]
    journal = gate_journal(db, world, execution_id)
    assert held(admin_engine, world, execution_id) == GRANTED

    refused = send(client, execution_id, report_body(world, secret, journal=journal))
    assert refused.status_code == 400, refused.text
    assert refused.json()["code"] == "INVALID_RECORD"
    assert held(admin_engine, world, execution_id) == GRANTED

    record = signed_record(db, world, execution_id)
    settled = send(client, execution_id, report_body(world, secret, record=record))
    assert settled.status_code == 200, settled.text
    assert held(admin_engine, world, execution_id) == (
        "EXECUTED",
        "ATTESTED",
        "CONFIRMED",
        "RELEASED",
    )


@pytest.mark.parametrize("declared", ["ENFORCED_BY_PROVIDER", "ASSERTED_BY_EXECUTOR"])
def test_a_journal_of_the_grants_own_command_still_settles_provider_verified(
    db, deployments, gate_world, admin_engine, declared
):
    world = gate_world
    client = deployments(declared)
    (action,) = targets(admin_engine, world, count=1)
    answer = ask(client, action)
    execution_id = answer["execution_id"]
    grant = answer["checkpoint"]["grant"]
    journal = gate_journal(db, world, execution_id)
    assert journal["record"]["command"] == grant["provider_command"]

    settled = send(
        client, execution_id, report_body(world, grant["report_secret"], journal=journal)
    )
    assert settled.status_code == 200, settled.text
    assert held(admin_engine, world, execution_id) == PROVIDER_VERIFIED


@pytest.mark.parametrize("issued", ["UNAVAILABLE", "ENFORCED_BY_PROVIDER"])
def test_a_grant_issued_before_the_class_was_recorded_still_takes_a_journal(
    db, deployments, gate_world, admin_engine, issued
):
    """A grant an earlier version issued carries no recorded class, and stays reportable only
    within a report window of the last grant an earlier version issued. An empty class cannot
    say which of the two classes it was issued under, so refusing would refuse legitimate
    journals too: it is accepted, as it was before, for either."""
    world = gate_world
    client = deployments(issued)
    (action,) = targets(admin_engine, world, count=1)
    answer = ask(client, action)
    execution_id = answer["execution_id"]
    forget_class(admin_engine, world, execution_id)
    assert recorded_class(admin_engine, world, execution_id) is None

    journal = gate_journal(db, world, execution_id)
    secret = answer["checkpoint"]["grant"]["report_secret"]
    settled = send(client, execution_id, report_body(world, secret, journal=journal))
    assert settled.status_code == 200, settled.text
    assert held(admin_engine, world, execution_id) == PROVIDER_VERIFIED


@pytest.mark.parametrize(
    ("issued", "later", "settles"),
    [
        ("UNAVAILABLE", "ENFORCED_BY_PROVIDER", False),
        ("ENFORCED_BY_PROVIDER", "UNAVAILABLE", True),
        ("UNAVAILABLE", "CHECKED_BY_CONNECTOR", False),
        ("ENFORCED_BY_PROVIDER", "CHECKED_BY_CONNECTOR", True),
    ],
    ids=[
        "declared after the grant",
        "withdrawn after the grant",
        "unavailable, then checked by a connector",
        "enforced, then checked by a connector",
    ],
)
def test_a_retry_after_the_declaration_changes_keeps_the_class_the_grant_was_issued_under(
    db, deployments, gate_world, admin_engine, issued, later, settles
):
    """The same request retried through a redeployment that declares the binding otherwise is
    answered the same grant again, described under the class it was issued under: a grant issued
    UNAVAILABLE is never shown a provider command, and a journal for it is refused. Nothing is
    written by that answer, so the recorded class, and what a journal is weighed against, stay
    the class the grant was issued under. A redeployment to CHECKED_BY_CONNECTOR, under which
    no grant is issued, changes nothing either: the grant is already issued, cannot be recalled,
    and the retry hands out no new secret."""
    world = gate_world
    first = deployments(issued)
    (action,) = targets(admin_engine, world, count=1)
    answer = ask(first, action)
    execution_id = answer["execution_id"]
    secret = answer["checkpoint"]["grant"]["report_secret"]

    redeployed = deployments(later)
    again = ask(redeployed, action)
    assert again["execution_id"] == execution_id
    assert again["checkpoint"]["grant"]["regranted"] is True
    assert again["checkpoint"]["grant"]["report_secret"] is None
    assert again["checkpoint"]["grant"]["precondition_class"] == issued
    assert ("provider_command" in again["checkpoint"]["grant"]) == (issued != "UNAVAILABLE")
    assert again["checkpoint"]["grant"].get("provider_command") == (
        answer["checkpoint"]["grant"].get("provider_command")
    )
    assert (
        again["checkpoint"]["grant"]["expected_version"]
        == (answer["checkpoint"]["grant"]["expected_version"])
    )
    assert recorded_class(admin_engine, world, execution_id) == issued
    assert granted_classes(admin_engine, world, execution_id) == [issued, issued]

    journal = gate_journal(db, world, execution_id)
    answered = send(redeployed, execution_id, report_body(world, secret, journal=journal))
    if settles:
        assert answered.status_code == 200, answered.text
        assert held(admin_engine, world, execution_id) == PROVIDER_VERIFIED
    else:
        assert answered.status_code == 400, answered.text
        assert answered.json()["code"] == "INVALID_RECORD"
        assert held(admin_engine, world, execution_id) == GRANTED


def test_a_retry_of_a_grant_with_no_recorded_class_is_described_as_it_was(
    deployments, gate_world, admin_engine
):
    """A grant an earlier release issued recorded no class, so a retry of it is described under
    the declaration in force, as every retry was, and writes nothing."""
    world = gate_world
    first = deployments("UNAVAILABLE")
    (action,) = targets(admin_engine, world, count=1)
    execution_id = ask(first, action)["execution_id"]
    forget_class(admin_engine, world, execution_id)

    again = ask(deployments("ENFORCED_BY_PROVIDER"), action)
    assert again["checkpoint"]["grant"]["regranted"] is True
    assert again["checkpoint"]["grant"]["precondition_class"] == "ENFORCED_BY_PROVIDER"
    assert "provider_command" in again["checkpoint"]["grant"]
    assert recorded_class(admin_engine, world, execution_id) is None


def test_the_administrators_settlement_still_takes_a_journal_under_an_unavailable_grant(
    db, deployments, gate_world, admin_engine
):
    """The refusal is the outcome route's alone. The journal the route refuses for a grant
    issued UNAVAILABLE settles it through the administrator's settlement in the console, which
    checks it under the journal key the deployment configured for the Gate account."""
    world = gate_world
    client = deployments("UNAVAILABLE")
    (action,) = targets(admin_engine, world, count=1)
    answer = ask(client, action)
    execution_id = answer["execution_id"]
    secret = answer["checkpoint"]["grant"]["report_secret"]
    journal = gate_journal(db, world, execution_id)
    refused = send(client, execution_id, report_body(world, secret, journal=journal))
    assert refused.status_code == 400, refused.text
    assert refused.json()["code"] == "INVALID_RECORD"
    assert held(admin_engine, world, execution_id) == GRANTED

    with console(db, world, admin_engine, checkpoint_providers=[journal_provider(world)]) as admin:
        settled = settle_from_console(
            admin,
            execution_id,
            reason="settled from the provider's journal",
            record=json.dumps(journal),
        )
        assert settled.status_code == 200, settled.text
    assert held(admin_engine, world, execution_id) == PROVIDER_VERIFIED
    assert recorded_class(admin_engine, world, execution_id) == "UNAVAILABLE"


def test_the_recorded_class_changes_nothing_the_record_shows(
    db, deployments, gate_world, admin_engine
):
    """The record describes an issued grant by no class and points at the grant's own audit
    events, and reads the column only for an operation ExecBound dispatched; the console's
    answer about a grant is the same with the class recorded and without it."""
    world = gate_world
    client = deployments("ENFORCED_BY_PROVIDER")
    (action,) = targets(admin_engine, world, count=1)
    execution_id = ask(client, action)["execution_id"]
    assert recorded_class(admin_engine, world, execution_id) == "ENFORCED_BY_PROVIDER"

    def shown() -> tuple[object, object]:
        with console(
            db, world, admin_engine, preconditions=DECLARED["ENFORCED_BY_PROVIDER"]
        ) as admin:
            detail = json.loads(article(admin, execution_id))
        return detail["checkpoint"], detail["dispatch"]

    recorded = shown()
    assert recorded[1] is None
    assert "Not shown for this record." in json.dumps(recorded[0])
    forget_class(admin_engine, world, execution_id)
    assert shown() == recorded
