# SPDX-License-Identifier: AGPL-3.0-only
"""What the console and the classic approval page show of a signal fact (docs/SIGNALS.md, "What
people see")."""

import re
from datetime import timedelta
from uuid import UUID

import pytest
from console_api_fixtures import API, console_client
from signal_fixtures import PRODUCER, default_space, insert_source, post_signal, register
from signal_fixtures import signal_world as signal_world
from space_fixtures import make_space, seat
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from test_console_api_tokens import application, auth, minted_for
from test_execution import request
from test_execution import world as world
from test_migration_without_bypass import fenced
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_resolution import registry as registry
from test_runtime import api as api
from test_runtime import runtime as runtime

from execbound.execution import store
from execbound.provisioning import ProvisioningError


def frozen_record(admin_engine, world, execution_id):
    """The one record the execution's frozen plan holds for its signal fact, as JSON."""
    with admin_engine.begin() as conn:
        fenced(conn, world["identity"].tenant_id)
        row = (
            conn.execute(
                text(
                    "SELECT frozen FROM execbound.executions "
                    "WHERE tenant_id = :t AND execution_id = :e"
                ),
                {"t": world["identity"].tenant_id, "e": execution_id},
            )
            .mappings()
            .one()
        )
    signal = store.frozen(dict(row)).fact("compromise").signal
    assert signal is not None
    [record] = signal.records
    return record.model_dump(mode="json")


def test_an_approver_sees_the_value_the_label_and_the_capability(
    api, db, runtime, admin_engine, signal_world
):
    post_signal(db, signal_world, "None")
    pending = api.post("/v1/execute", json=request(signal_world).model_dump(mode="json")).json()
    with console_client(db, runtime, admin_engine, signal_world["human"]) as client:
        detail = client.get(f"/api/console/v1/approvals/{pending['approval_id']}").json()
    [fact] = [item for item in detail["facts"] if item["name"] == "compromise"]
    assert fact["value"] == "no_detection"
    assert fact["source_kind"] == "signal"
    assert fact["source_label"] == "MDE lab"
    assert fact["capability"] == "resource_compromise.v1"
    assert "attributes" not in fact and "records" not in fact
    role = next(item for item in detail["facts"] if item["name"] == "role")
    assert role["source_label"] is None and role["capability"] is None


def test_an_approver_reads_the_capability_but_not_the_records(
    api, db, runtime, admin_engine, signal_world
):
    """The execution's page admits an approver too; the records are an administrator's."""
    post_signal(db, signal_world, "None")
    pending = api.post("/v1/execute", json=request(signal_world).model_dump(mode="json")).json()
    with console_client(db, runtime, admin_engine, signal_world["human"]) as client:
        detail = client.get(f"/api/console/v1/executions/{pending['execution_id']}").json()
    [fact] = [item for item in detail["facts"] if item["name"] == "compromise"]
    assert fact["capability"] == "resource_compromise.v1"
    assert fact["source_label"] == "MDE lab"
    assert fact["records"] is None


def test_an_administrator_sees_the_record(api, db, runtime, admin_engine, signal_world):
    now = signal_world["clock"].now()
    # Observed half a minute before it was received, so the two instants cannot be swapped.
    post_signal(
        db,
        signal_world,
        "Medium",
        observed_at=now - timedelta(seconds=30),
        expires_at=now + timedelta(minutes=4),
    )
    executed = api.post("/v1/execute", json=request(signal_world).model_dump(mode="json")).json()
    with console_client(db, runtime, admin_engine, signal_world["admin"]) as client:
        detail = client.get(f"/api/console/v1/executions/{executed['execution_id']}").json()
    [fact] = [item for item in detail["facts"] if item["name"] == "compromise"]
    assert fact["capability"] == "resource_compromise.v1"
    assert fact["source_label"] == "MDE lab"
    [record] = fact["records"]
    # Every field of the record the plan froze, and nothing else: no attributes, which no plan
    # holds, and no field the frozen record does not carry.
    assert record == frozen_record(admin_engine, signal_world, executed["execution_id"])
    assert (record["verdict"], record["confidence"]) == ("Medium", 1000)
    assert record["source_id"] == str(signal_world["source"])
    assert record["observed_at"] != record["received_at"]
    assert record["expires_at"] is not None
    assert "attributes" not in record
    # Every other fact carries none of it.
    role = next(item for item in detail["facts"] if item["name"] == "role")
    assert role["capability"] is None and role["records"] is None
    assert role["source_label"] is None


def test_an_administrators_token_reads_the_records(api, db, runtime, signal_world):
    """A token reads as the administrator who owns it, so it reads the records too."""
    post_signal(db, signal_world, "Medium")
    executed = api.post("/v1/execute", json=request(signal_world).model_dump(mode="json")).json()
    token = minted_for(runtime, signal_world["admin"])
    with application(db, runtime) as client:
        read = client.get(API + f"/executions/{executed['execution_id']}", headers=auth(token))
    [fact] = [item for item in read.json()["facts"] if item["name"] == "compromise"]
    assert [record["verdict"] for record in fact["records"]] == ["Medium"]


# What a producer may send beside its verdict. Each carries "canary", so one search finds any of
# them wherever it leaked; the digest is hex and is searched for on its own.
CANARY_ATTRIBUTES = {f"canary_name_{index:02}": f"canary-value-{index:02}" for index in range(16)}
CANARY_REF = "https://canary.invalid/x"
CANARY_DIGEST = "cafe" * 16
PROBE = "device-01:severity-probe"


def leaked(text: str) -> bool:
    return "canary" in text or CANARY_DIGEST in text


@pytest.mark.parametrize("severity", ["Critical", "Informational"])
def test_severity_attributes_and_evidence_never_leave_the_record(
    api, db, runtime, admin_engine, signal_world, severity
):
    """Severity, attributes and the evidence reference and digest stay in `security_signals`
    (THREAT_MODEL.md T13.4, T13.7, T13.8). No frozen plan, audit payload, agent answer or
    console view carries them, and the severity a producer claims changes no decision: `None`
    goes to review whether the producer calls it Critical or Informational."""
    tenant = signal_world["identity"].tenant_id
    admitted = post_signal(
        db,
        signal_world,
        "None",
        event_id=PROBE,
        severity=f"{severity} sevcanary",
        attributes=CANARY_ATTRIBUTES,
        evidence_ref=CANARY_REF,
        evidence_digest=CANARY_DIGEST,
    )
    assert admitted.get("accepted") is True, admitted
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        stored = (
            conn.execute(
                text(
                    "SELECT severity, attributes, evidence_ref, evidence_digest "
                    "FROM execbound.security_signals WHERE tenant_id = :t AND source_event_id = :e"
                ),
                {"t": tenant, "e": PROBE},
            )
            .mappings()
            .one()
        )
    # The record holds every canary, so their absence below is the product's doing.
    assert dict(stored) == {
        "severity": f"{severity} sevcanary",
        "attributes": CANARY_ATTRIBUTES,
        "evidence_ref": CANARY_REF,
        "evidence_digest": CANARY_DIGEST,
    }
    pending = api.post("/v1/execute", json=request(signal_world).model_dump(mode="json"))
    assert (pending.status_code, pending.json()["state"]) == (202, "PENDING_APPROVAL")
    execution, approval = pending.json()["execution_id"], pending.json()["approval_id"]
    status = api.get(f"/v1/executions/{execution}")
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        frozen = conn.execute(
            text(
                "SELECT frozen::text FROM execbound.executions "
                "WHERE tenant_id = :t AND execution_id = :e"
            ),
            {"t": tenant, "e": execution},
        ).scalar_one()
        events = conn.execute(
            text("SELECT kind, payload::text FROM execbound.audit_events WHERE tenant_id = :t"),
            {"t": tenant},
        ).all()
    evaluated = [payload for kind, payload in events if kind == "execution.evaluated"]
    # The plan and its decision capture do carry the record, so the search reads the right text.
    assert PROBE in frozen and evaluated and all(PROBE in payload for payload in evaluated)
    with console_client(db, runtime, admin_engine, signal_world["human"]) as client:
        approver = client.get(f"/api/console/v1/approvals/{approval}")
        classic = client.get(f"/approvals/{approval}/classic")
    with console_client(db, runtime, admin_engine, signal_world["admin"]) as client:
        administrator = client.get(f"/api/console/v1/executions/{execution}")
    assert approver.status_code == classic.status_code == administrator.status_code == 200
    assert PROBE in administrator.text
    for where, content in (
        ("frozen plan", frozen),
        *((f"audit {kind}", payload) for kind, payload in events),
        ("agent answer", pending.text),
        ("agent status", status.text),
        ("approver view", approver.text),
        ("classic approval page", classic.text),
        ("administrator view", administrator.text),
    ):
        assert not leaked(content), where


def fact_row(page: str, name: str) -> str:
    """One fact's row of the classic page's table of trusted facts."""
    [row] = re.findall(rf'<tr><th scope="row">{name}</th>.*?</tr>', page, re.S)
    return row


def test_the_classic_page_names_the_label_and_the_capability_and_nothing_of_the_record(
    api, db, runtime, admin_engine, signal_world
):
    """The server-rendered approval page, which a phone whose console does not load decides on
    (#333), names a signal fact's producer by its registered label and the capability it answers,
    as the console's approval detail does. It renders nothing of the frozen record and nothing the
    producer sent beside its verdict."""
    post_signal(
        db,
        signal_world,
        "None",
        event_id=PROBE,
        severity="Critical sevcanary",
        attributes=CANARY_ATTRIBUTES,
        evidence_ref=CANARY_REF,
        evidence_digest=CANARY_DIGEST,
    )
    pending = api.post("/v1/execute", json=request(signal_world).model_dump(mode="json")).json()
    with console_client(db, runtime, admin_engine, signal_world["human"]) as client:
        page = client.get(f"/approvals/{pending['approval_id']}/classic")
    assert page.status_code == 200
    compromise = fact_row(page.text, "compromise")
    assert "<td>no_detection</td>" in compromise
    # The label is registered text, isolated so its direction cannot reorder the capability.
    assert "signal · <bdi>MDE lab</bdi> (resource_compromise.v1)" in compromise
    # Every other fact names its source's kind alone.
    role = fact_row(page.text, "role")
    assert "<bdi>" not in role and "resource_compromise" not in role and "MDE lab" not in role
    # Nothing of the record: not its event id, its producer or its verdict's severity, and none
    # of what the producer sent beside the verdict.
    assert PROBE not in page.text and PRODUCER not in page.text and "Critical" not in page.text
    assert not leaked(page.text)


OTHER_SPACE = "Customer B"


def give_source_to_another_space(admin_engine, world, *, offered: bool) -> UUID:
    """Hand the world's source to a second space after a plan froze it; returns that space.

    Production has no path that moves a source or withdraws its offer, so this is the owner
    writing a fixture, as `space_fixtures.place` is for the owned tables. It stands for any
    way a row a reader may see comes to name a source their spaces cannot use.
    """
    tenant = world["identity"].tenant_id
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        other = make_space(conn, tenant, OTHER_SPACE)
        moved = conn.execute(
            text(
                "UPDATE execbound.signal_sources SET space_id = :s, offered_tenant_wide = :o "
                "WHERE tenant_id = :t AND source_id = :i"
            ),
            {"s": other, "o": offered, "t": tenant, "i": world["source"]},
        )
        assert moved.rowcount == 1
    return other


def pending_signal_approval(api, db, world) -> dict:
    """One request held for review on a `None` verdict, in the world's own space."""
    post_signal(db, world, "None")
    pending = api.post("/v1/execute", json=request(world).model_dump(mode="json"))
    assert (pending.status_code, pending.json()["state"]) == (202, "PENDING_APPROVAL")
    return pending.json()


def compromise(read) -> dict:
    assert read.status_code == 200, read.text
    [fact] = [item for item in read.json()["facts"] if item["name"] == "compromise"]
    return fact


def test_a_label_of_another_spaces_source_is_withheld_from_a_reader_of_this_one(
    api, db, runtime, admin_engine, signal_world
):
    """The label reader takes the shared space predicate (THREAT_MODEL.md R25, T13.12).

    An approver seated in this space alone opens an approval in it whose frozen plan names a
    source another space owns and does not offer. The approval and the execution answer the
    signal fact with its value and capability and no label, which the console names by the
    fact's kind, and the classic page lists it as kind `signal` with its capability: no
    error, no blank, and nothing of the other space's source. A workspace-wide reader still
    reads the label on the same execution.
    """
    pending = pending_signal_approval(api, db, signal_world)
    give_source_to_another_space(admin_engine, signal_world, offered=False)
    with console_client(db, runtime, admin_engine, signal_world["human"]) as client:
        approval = client.get(f"{API}/approvals/{pending['approval_id']}")
        execution = client.get(f"{API}/executions/{pending['execution_id']}")
        classic = client.get(f"/approvals/{pending['approval_id']}/classic")
    for read in (approval, execution):
        fact = compromise(read)
        assert fact["source_label"] is None
        assert fact["source_kind"] == "signal"
        assert fact["capability"] == "resource_compromise.v1"
        assert fact["value"] == "no_detection"
    assert classic.status_code == 200
    row = fact_row(classic.text, "compromise")
    assert "<td>no_detection</td>" in row
    assert "resolved · signal (resource_compromise.v1)<br>" in row and "<bdi>" not in row
    for read in (approval, execution, classic):
        assert "MDE lab" not in read.text and OTHER_SPACE not in read.text
    with console_client(db, runtime, admin_engine, signal_world["admin"]) as client:
        workspace = client.get(f"{API}/executions/{pending['execution_id']}")
    assert compromise(workspace)["source_label"] == "MDE lab"


def test_a_source_offered_tenant_wide_keeps_its_label_in_every_space(
    api, db, runtime, admin_engine, signal_world
):
    """An offered source is usable by every space, so a reader of any space reads its label."""
    pending = pending_signal_approval(api, db, signal_world)
    give_source_to_another_space(admin_engine, signal_world, offered=True)
    with console_client(db, runtime, admin_engine, signal_world["human"]) as client:
        approval = client.get(f"{API}/approvals/{pending['approval_id']}")
        execution = client.get(f"{API}/executions/{pending['execution_id']}")
        classic = client.get(f"/approvals/{pending['approval_id']}/classic")
    assert compromise(approval)["source_label"] == "MDE lab"
    assert compromise(execution)["source_label"] == "MDE lab"
    assert "signal · <bdi>MDE lab</bdi> (resource_compromise.v1)" in fact_row(
        classic.text, "compromise"
    )


def test_a_member_of_the_sources_space_reads_its_label_whatever_space_they_look_at(
    api, db, runtime, admin_engine, signal_world
):
    """Membership is the authority and the current space only a view: a label is read under
    the same visible set as the one record it belongs to, which is named by its identifier."""
    pending = pending_signal_approval(api, db, signal_world)
    other = give_source_to_another_space(admin_engine, signal_world, offered=False)
    tenant = signal_world["identity"].tenant_id
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        seat(conn, tenant, other, signal_world["human"].principal_id)
        own = default_space(conn, tenant)
    with console_client(db, runtime, admin_engine, signal_world["human"]) as client:
        looking = client.post(f"{API}/session/space", {"space_id": str(own)})
        assert looking.status_code == 200, looking.text
        approval = client.get(f"{API}/approvals/{pending['approval_id']}")
        execution = client.get(f"{API}/executions/{pending['execution_id']}")
    assert compromise(approval)["source_label"] == "MDE lab"
    assert compromise(execution)["source_label"] == "MDE lab"


@pytest.mark.parametrize(
    "label",
    ["MDE <b>lab</b>", "MDE lab & co", "MDE \u202elab"],
    ids=["markup", "ampersand", "direction override"],
)
def test_a_label_the_classic_page_would_have_to_escape_is_never_registered(
    world, admin_engine, tmp_path, label
):
    """Why the classic page's test above names a plain label: no other can reach the page.

    The page prints a source's label inside `<bdi>` through an autoescaping environment, but
    a label with markup, an ampersand or a direction override is refused before any page
    reads it: by the registration command, and again by the table's own check, which binds
    the owner too.
    """
    with pytest.raises(ProvisioningError) as refused:
        register(admin_engine, world, tmp_path / "signal-token", label=label)
    assert refused.value.code == "INVALID_LABEL"
    assert not (tmp_path / "signal-token").exists()
    tenant = world["identity"].tenant_id
    with pytest.raises(IntegrityError, match='check constraint "signal_sources_label_check"'):
        with admin_engine.begin() as conn:
            fenced(conn, tenant)
            insert_source(
                conn, tenant, world["admin"].principal_id, world["clock"].now(), label=label
            )
