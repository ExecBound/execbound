# SPDX-License-Identifier: AGPL-3.0-only
"""The assistant's turn rows: written only through the definer functions, read only by the
person who asked, bounded, abandoned honestly, retired on time; and the tenant switch."""

import json
import os
import re
import sys
from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from test_emergency_stop import audit
from test_execution import provision_identity
from test_execution import registry as registry
from test_execution import world as world
from test_human_surface import credential

from execbound.assistant import turns
from execbound.assistant.client import Usage
from execbound.assistant.config import PROVIDER_RETENTION
from execbound.assistant.turns import (
    AssistantError,
    Caps,
    append_step,
    complete_turn,
    create_turn,
    list_turns,
    read_turn,
    retire_turns,
    set_tenant_switch,
    tenant_switch,
)
from execbound.cli import main
from execbound.db import FUNCTIONS, TABLES, check_runtime

pytestmark = pytest.mark.integration

ANSWER = {
    "paragraphs": [{"text": "Denied by rule isolate-never-domain-controller.", "ids": ["a"]}],
    "cannot_answer": False,
}


def switched_on(db, world):
    return set_tenant_switch(db, world["admin"], True, "The sandbox is synthetic", world["clock"])


def new_turn(db, world, identity=None, **changes):
    values = {
        "context_kind": "question",
        "context_id": None,
        "question": "Why was device-01 denied?",
        "model": "scripted",
        "clock": world["clock"],
    }
    values.update(changes)
    return create_turn(db, identity or world["human"], **values)


def finish(db, world, turn, **changes):
    return complete_turn(db, world["human"], turn.turn_id, clock=world["clock"], **changes)


def long_lived(db, admin_engine, world):
    """The world's people again, with credentials that outlive a month of clock; the clock
    jumps below would otherwise expire the two-hour ones and refuse the identity."""
    tenant, now = world["identity"].tenant_id, world["clock"].now()
    return {
        **world,
        "admin": provision_identity(admin_engine, db, tenant, "ADMIN", now, timedelta(days=40)),
        "human": provision_identity(
            admin_engine, db, tenant, "HUMAN_APPROVER", now, timedelta(days=40)
        ),
    }


def test_the_schema_carries_the_table_the_functions_and_the_switch(db, admin_engine, world):
    assert "assistant_turns" in TABLES
    assert {name for name, _ in FUNCTIONS} >= {
        "assistant_turn_create",
        "assistant_turn_step",
        "assistant_turn_complete",
        "assistant_turn_retire",
    }
    with db.engine.connect() as conn:
        check_runtime(conn)
    tenant = world["identity"].tenant_id
    # The runtime role holds no write on the table: every path below goes through a function.
    for statement in (
        "INSERT INTO execbound.assistant_turns (tenant_id, turn_id, principal_id, context_kind, "
        "state, model, created_at) VALUES (:t, gen_random_uuid(), :p, 'question', 'RUNNING', "
        "'x', now())",
        "UPDATE execbound.assistant_turns SET state = 'FAILED' WHERE tenant_id = :t AND :p = :p",
        "DELETE FROM execbound.assistant_turns WHERE tenant_id = :t AND :p = :p",
    ):
        with pytest.raises(DBAPIError), db.transaction(tenant) as conn:
            conn.execute(text(statement), {"t": tenant, "p": world["human"].principal_id})


def test_every_code_the_assistant_passes_on_is_one_something_it_calls_raises(db, admin_engine):
    """`CODES` is the list of refusals the assistant passes on; any other reads
    `ASSISTANT_UNAVAILABLE`. Each code on it must be one that a database function this module
    calls raises, that the assistant raises itself, or that the identity check or the policy
    store a rule draft reads can answer, or it documents a refusal nobody can meet. Every
    code those functions raise must be on it, or a person's refusal reads as unavailability."""
    source = Path(turns.__file__).read_text(encoding="utf-8")
    called = set(re.findall(r"execbound\.(assistant_turn_\w+)\(", source))
    with admin_engine.connect() as conn:
        bodies = (
            conn.execute(
                text(
                    "SELECT pg_get_functiondef(p.oid) FROM pg_proc p "
                    "JOIN pg_namespace n ON n.oid = p.pronamespace "
                    "WHERE n.nspname = 'execbound' AND p.proname = ANY(:names)"
                ),
                {"names": sorted(called)},
            )
            .scalars()
            .all()
        )
    assert len(bodies) == len(called) == 5
    definers = {code for body in bodies for code in re.findall(r"RAISE EXCEPTION '(\w+)'", body)}
    assistant = Path(turns.__file__).parent
    store = assistant.parent / "policy" / "store.py"
    raised = {
        code
        for path in [*assistant.glob("*.py"), store]
        for code in re.findall(r'Error\("([A-Z_]+)"', path.read_text(encoding="utf-8"))
    }
    assert definers <= turns.CODES
    assert turns.CODES - definers - raised == set(), "passed on, but nothing raises it"


def test_the_switch_is_off_until_an_admin_turns_it_on_with_a_reason(db, admin_engine, world):
    tenant = world["identity"].tenant_id
    with db.transaction(tenant) as conn:
        assert tenant_switch(conn, tenant) is False
    with pytest.raises(AssistantError) as off:
        new_turn(db, world)
    assert off.value.code == "ASSISTANT_OFF"
    for reason in ("", "x" * 501):
        with pytest.raises(AssistantError) as refused:
            set_tenant_switch(db, world["admin"], True, reason, world["clock"])
        assert refused.value.code == "INVALID_REASON"
    with pytest.raises(AssistantError) as approver:
        set_tenant_switch(db, world["human"], True, "Not mine to set", world["clock"])
    assert approver.value.code == "INVALID_IDENTITY"
    change = switched_on(db, world)
    assert (change.previous, change.enabled) == (False, True)
    with pytest.raises(AssistantError) as again:
        switched_on(db, world)
    assert again.value.code == "INVALID_STATE"
    payloads = audit(admin_engine, tenant, "tenant.assistant_changed")
    assert len(payloads) == 1
    assert payloads[0]["previous"] is False and payloads[0]["enabled"] is True
    assert payloads[0]["reason"] == "The sandbox is synthetic"
    off_again = set_tenant_switch(db, world["admin"], False, "Trial over", world["clock"])
    assert off_again.enabled is False


def test_a_turn_runs_steps_completes_once_and_is_read_back_whole(db, world):
    switched_on(db, world)
    turn = new_turn(db, world)
    assert turn.state == "RUNNING" and turn.steps == () and turn.completed_at is None
    step = lambda text: append_step(db, world["human"], turn.turn_id, text, world["clock"])  # noqa: E731
    assert step("Read the active policy") == 1
    assert step("Read 3 denials") == 2
    with pytest.raises(AssistantError) as long_step:
        step("x" * 201)
    assert long_step.value.code == "INVALID_STEP"
    finish(
        db,
        world,
        turn,
        state="COMPLETED",
        answer=ANSWER,
        cited_ids=["a"],
        tool_names=["get_policy", "list_executions"],
        usage=Usage(input_tokens=1200, output_tokens=80, cache_read_input_tokens=900),
    )
    done = read_turn(db, world["human"], turn.turn_id, world["clock"])
    assert done.state == "COMPLETED" and done.reason is None
    assert done.steps == ("Read the active policy", "Read 3 denials")
    assert done.answer == ANSWER and done.cited_ids == ("a",)
    assert done.tool_names == ("get_policy", "list_executions")
    assert (done.input_tokens, done.cached_tokens, done.output_tokens) == (1200, 900, 80)
    assert done.completed_at is not None and done.retired_at is None
    # Once completed, nothing moves it.
    with pytest.raises(AssistantError) as late_step:
        step("late")
    assert late_step.value.code == "INVALID_STATE"
    with pytest.raises(AssistantError) as closed:
        finish(db, world, turn, state="FAILED", reason="MODEL_ERROR")
    assert closed.value.code == "INVALID_STATE"
    assert [t.turn_id for t in list_turns(db, world["human"], world["clock"])] == [turn.turn_id]


def test_a_failure_carries_one_reason_from_the_closed_list_and_nothing_else(db, world):
    switched_on(db, world)
    turn = new_turn(db, world)
    for state, reason, answer, code in (
        ("FAILED", "BECAUSE", None, "INVALID_REASON"),
        ("FAILED", None, None, "INVALID_REASON"),
        ("FAILED", "TOOL_LIMIT", ANSWER, "INVALID_REASON"),
        ("COMPLETED", None, None, "INVALID_ANSWER"),
        ("COMPLETED", "TOOL_LIMIT", ANSWER, "INVALID_ANSWER"),
        ("DONE", None, ANSWER, "INVALID_STATE"),
    ):
        with pytest.raises(AssistantError) as refused:
            finish(db, world, turn, state=state, reason=reason, answer=answer)
        assert refused.value.code == code, (state, reason)
    finish(db, world, turn, state="FAILED", reason="TOOL_LIMIT")
    failed = read_turn(db, world["human"], turn.turn_id, world["clock"])
    assert (failed.state, failed.reason, failed.answer) == ("FAILED", "TOOL_LIMIT", None)


def test_turns_are_private_to_the_person_who_asked(db, world):
    switched_on(db, world)
    theirs = new_turn(db, world)
    reader = world["admin"]
    with pytest.raises(AssistantError) as hidden:
        read_turn(db, reader, theirs.turn_id, world["clock"])
    assert hidden.value.code == "INVALID_TURN"
    assert list_turns(db, reader, world["clock"]) == []
    with pytest.raises(AssistantError) as not_theirs:
        append_step(db, reader, theirs.turn_id, "prying", world["clock"])
    assert not_theirs.value.code == "INVALID_TURN"
    # An agent principal can own no turn at all.
    with pytest.raises(AssistantError) as agent:
        new_turn(db, world, world["identity"])
    assert agent.value.code == "INVALID_IDENTITY"


def test_another_tenant_reads_no_turn(db, world, seeded):
    """The tenant fence on `assistant_turns` itself, read as the runtime role (#155): a turn is
    there for its own workspace and absent under another workspace's fence."""
    switched_on(db, world)
    turn = new_turn(db, world)
    tenant = world["identity"].tenant_id
    other = next(candidate for candidate in seeded["tenants"] if candidate != tenant)
    with db.transaction(other) as conn:
        assert (
            conn.execute(text("SELECT count(*) FROM execbound.assistant_turns")).scalar_one() == 0
        )
    with db.transaction(tenant) as conn:
        assert conn.execute(
            text("SELECT turn_id FROM execbound.assistant_turns")
        ).scalars().all() == [turn.turn_id]


def test_a_turn_left_running_reads_abandoned_after_ninety_seconds(db, world):
    switched_on(db, world)
    turn = new_turn(db, world)
    world["clock"].value = world["clock"].now() + timedelta(seconds=89)
    assert read_turn(db, world["human"], turn.turn_id, world["clock"]).state == "RUNNING"
    world["clock"].value = world["clock"].now() + timedelta(seconds=2)
    stale = read_turn(db, world["human"], turn.turn_id, world["clock"])
    assert (stale.state, stale.reason) == ("FAILED", "ABANDONED")
    assert stale.completed_at is not None
    # Persisted, so the loop that comes back late cannot complete it.
    with pytest.raises(AssistantError) as late:
        finish(db, world, turn, state="COMPLETED", answer=ANSWER)
    assert late.value.code == "INVALID_STATE"


def test_retirement_nulls_the_text_at_thirty_days_and_keeps_the_counts(db, admin_engine, world):
    world = long_lived(db, admin_engine, world)
    switched_on(db, world)
    turn = new_turn(db, world)
    append_step(db, world["human"], turn.turn_id, "Read the policy", world["clock"])
    finish(
        db, world, turn, state="COMPLETED", answer=ANSWER, cited_ids=["a"], usage=Usage(10, 5, 3)
    )
    with pytest.raises(AssistantError) as approver:
        retire_turns(db, world["human"], world["clock"])
    assert approver.value.code == "INVALID_IDENTITY"
    world["clock"].value = world["clock"].now() + timedelta(days=29, hours=23)
    assert retire_turns(db, world["admin"], world["clock"]) == 0
    world["clock"].value = world["clock"].now() + timedelta(hours=2)
    assert retire_turns(db, world["admin"], world["clock"]) == 1
    assert retire_turns(db, world["admin"], world["clock"]) == 0
    retired = read_turn(db, world["human"], turn.turn_id, world["clock"])
    assert retired.question is None and retired.steps == () and retired.answer is None
    assert retired.cited_ids == () and retired.retired_at is not None
    assert (retired.input_tokens, retired.output_tokens, retired.cached_tokens) == (10, 5, 3)
    assert retired.state == "COMPLETED"


def test_the_caps_refuse_the_next_turn_and_are_counted_in_the_same_transaction(
    db, admin_engine, world
):
    world = long_lived(db, admin_engine, world)
    switched_on(db, world)
    caps = Caps(person_hourly_turns=2, tenant_daily_tokens=100)
    first = new_turn(db, world, caps=caps)
    new_turn(db, world, caps=caps)
    with pytest.raises(AssistantError) as hourly:
        new_turn(db, world, caps=caps)
    assert hourly.value.code == "PERSON_LIMIT"
    # An hour on, the person may ask again; the tokens the first turn spent count for the day.
    world["clock"].value = world["clock"].now() + timedelta(hours=1, seconds=1)
    finish(db, world, first, state="COMPLETED", answer=ANSWER, usage=Usage(80, 20, 0))
    with pytest.raises(AssistantError) as daily:
        new_turn(db, world, caps=caps)
    assert daily.value.code == "TENANT_LIMIT"
    world["clock"].value = world["clock"].now() + timedelta(days=1)
    assert new_turn(db, world, caps=caps).state == "RUNNING"


def test_the_cli_sets_the_switch_with_a_reason_and_states_the_providers_retention(
    db, admin_engine, world, tmp_path, monkeypatch, capsys
):
    """`execbound tenant-assistant --set on|off --reason ...`, beside `tenant-mode`: an
    approver is refused, a no-op is refused, every change is audited, and the answer states
    what the provider keeps, so the person turning it on reads it at that moment."""
    tenant = world["identity"].tenant_id
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    monkeypatch.setenv("MIGRATION_DATABASE_URL", os.environ["TEST_MIGRATION_DATABASE_URL"])
    admin_file, human_file = tmp_path / "admin.txt", tmp_path / "human.txt"
    admin_file.write_text(credential(admin_engine, world["admin"]), encoding="utf-8")
    human_file.write_text(credential(admin_engine, world["human"]), encoding="utf-8")

    def run(*argv):
        monkeypatch.setattr(sys, "argv", ["execbound", *argv])
        main()
        return json.loads(capsys.readouterr().out)

    def refused(*argv):
        monkeypatch.setattr(sys, "argv", ["execbound", *argv])
        with pytest.raises(SystemExit) as caught:
            main()
        assert caught.value.code == 2
        return capsys.readouterr().err

    common = ("--tenant", str(tenant), "--credential-file")
    assert "INVALID_IDENTITY" in refused(
        "tenant-assistant", *common, str(human_file), "--set", "on", "--reason", "No"
    )
    changed = run("tenant-assistant", *common, str(admin_file), "--set", "on", "--reason", "Trial")
    assert changed == {
        "tenant_id": str(tenant),
        "assistant_enabled": True,
        "previous": False,
        "provider_retention": PROVIDER_RETENTION,
    }
    assert "INVALID_STATE" in refused(
        "tenant-assistant", *common, str(admin_file), "--set", "on", "--reason", "Again"
    )
    with db.transaction(tenant) as conn:
        assert tenant_switch(conn, tenant) is True
    off = run("tenant-assistant", *common, str(admin_file), "--set", "off", "--reason", "Done")
    assert off["assistant_enabled"] is False and off["previous"] is True
    reasons = [row["reason"] for row in audit(admin_engine, tenant, "tenant.assistant_changed")]
    assert reasons == ["Trial", "Done"]
