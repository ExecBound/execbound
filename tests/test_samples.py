# SPDX-License-Identifier: AGPL-3.0-only
"""Sample targets (#420): install, removal and refresh through `execbound.samples` (SM1, SM2,
SM6, SM9).

SM1 runs against the `restricted` fixture's database, whose owner does not bypass row
security, so the definer function and every fenced read here would find nothing rather than
pass if a statement forgot its tenant. The rest run on the ordinary test database, with real
admissions from the kernel for the requests a removal must not strand.
"""

import io
import json
import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from typing import get_args
from uuid import uuid4

import pytest
from sample_fixtures import agent_identity, empty_workspace, password_workspace, person
from signup_fixtures import chain
from signup_fixtures import stack as stack
from space_fixtures import make_space, seat
from sqlalchemy import text
from test_migration_without_bypass import fenced
from test_migration_without_bypass import restricted as restricted
from test_samples_schema import blocked_on_a_lock, select_policy

from execbound import logging_schema, samples
from execbound.execution import admit, mark_indeterminate, take_dispatch
from execbound.execution.models import UNRESOLVED, ExecutionError, ExecutionState
from execbound.policy.store import (
    PolicyStoreError,
    activate_bundle,
    activate_new_bundle,
    create_bundle,
    validate_bundle,
)
from execbound.provider.sample_accounts import SAMPLE_RESOURCE_VERSION
from execbound.recovery_run import expire_approval
from execbound.replay.export import export_history
from execbound.replay.simulate import simulate
from execbound.replay.verify import verify_export
from execbound.requests import parse_request
from execbound.resolution.models import SystemClock

pytestmark = pytest.mark.integration

REGISTRY = (
    "connector_accounts",
    "context_sources",
    "operation_mappings",
    "canonical_targets",
    "resources",
    "resource_identities",
    "resource_aliases",
    "incidents",
    "approval_scopes",
)
POLICY = ("policy_bundle_contents", "policy_bundle_lifecycle", "space_policy_selection")
# The rows a removal switches off, and what it switches.
DEACTIVATED = (
    "connector_accounts",
    "context_sources",
    "operation_mappings",
    "resources",
    "approval_scopes",
)


def rows(engine, tenant):
    """Every row a workspace's samples and policy are made of, and how long its chain is."""
    with engine.begin() as conn:
        fenced(conn, tenant)
        found = {
            table: sorted(
                str(dict(row))
                for row in conn.execute(
                    text(f"SELECT * FROM execbound.{table} WHERE tenant_id = :t"), {"t": tenant}
                ).mappings()
            )
            for table in (*REGISTRY, *POLICY, "tenant_policy_control")
        }
        found["audit_events"] = [
            str(
                conn.execute(
                    text("SELECT count(*) FROM execbound.audit_events WHERE tenant_id = :t"),
                    {"t": tenant},
                ).scalar_one()
            )
        ]
    return found


def request_for(host, key):
    return parse_request(
        json.dumps(
            {
                "operation_ref": "endpoint.isolate",
                "target": {"kind": "hostname", "value": host.hostname},
                "arguments": {},
                "idempotency_key": key,
                "claimed_context": {"incident_id": str(host.incident_id)},
            }
        ).encode()
    )


def by_effect(status):
    return {host.effect: host for host in status.hosts}


def _installed_host(*, incident_id) -> samples.SampleHost:
    target = samples.SAMPLE_TARGETS[0]
    return samples.SampleHost(
        provider_id=target.provider_id,
        hostname=target.hostname,
        role=target.role,
        environment=target.environment,
        criticality=target.criticality,
        canonical_target_id=uuid4(),
        incident_id=incident_id,
        effect="allow",
        rules=(target.rule_id,),
    )


def test_sample_workstation_names_the_first_targets_host_only_with_an_open_incident():
    """The one selection Home's Getting started page and the console's own connection route
    (#496) both call, so a page never picks the target out of `status.hosts` its own
    way: the installed host matching `SAMPLE_TARGETS[0]`, and only once it carries an incident."""
    open_incident = _installed_host(incident_id=uuid4())
    assert (
        samples.sample_workstation(
            samples.SampleStatus("removable", False, True, hosts=(open_incident,))
        )
        is open_incident
    )

    closed = _installed_host(incident_id=None)
    assert (
        samples.sample_workstation(samples.SampleStatus("removable", False, True, hosts=(closed,)))
        is None
    )

    assert samples.sample_workstation(samples.SampleStatus("absent", True, True)) is None

    other = samples.SampleHost(
        provider_id="sample-dc-01",
        hostname="dc-01.sample.invalid",
        role="domain_controller",
        environment="production",
        criticality=3,
        canonical_target_id=uuid4(),
        incident_id=uuid4(),
        effect="deny",
        rules=("isolate-never-domain-controller",),
    )
    assert (
        samples.sample_workstation(samples.SampleStatus("removable", False, True, hosts=(other,)))
        is None
    )


# The instant the demo's statuses are read at, half an hour after their facts were recorded,
# with the starter's hour still to run.
DEMO_NOW = datetime(2026, 10, 15, 12, 0, tzinfo=UTC)
DEMO_RECORDED = DEMO_NOW - timedelta(minutes=30)


def _demo_status(
    *,
    available=True,
    operation_ref=samples.SAMPLE_ACTION,
    closed=None,
    in_force=True,
    state="removable",
    changed=(),
    stopped=False,
):
    """Installed samples as `samples.status` reads them: each target with an open incident but
    the one whose effect is `closed`, under the starter the default space selects and enforces
    unless `in_force` is false, with no request on them unresolved unless `state` is
    `present`, and none that may have changed one at the provider since their facts were
    recorded but on the targets whose effects `changed` names, in a workspace under no
    emergency stop unless `stopped`. The facts were recorded at `DEMO_RECORDED` and go stale an
    hour later, as the starter keeps them."""
    hosts = tuple(
        samples.SampleHost(
            provider_id=target.provider_id,
            hostname=target.hostname,
            role=target.role,
            environment=target.environment,
            criticality=target.criticality,
            canonical_target_id=uuid4(),
            incident_id=None if target.expected == closed else uuid4(),
            effect=target.expected,
            rules=(target.rule_id,),
        )
        for target in samples.SAMPLE_TARGETS
    )
    return samples.SampleStatus(
        state,
        False,
        available,
        account_id=uuid4(),
        bundle_id=uuid4(),
        hosts=hosts,
        observed_at=DEMO_RECORDED,
        stale_at=DEMO_RECORDED + timedelta(hours=1),
        operation_ref=operation_ref,
        in_force=in_force,
        changed=frozenset(
            target.provider_id for target in samples.SAMPLE_TARGETS if target.expected in changed
        ),
        stopped=stopped,
    )


def test_sm11_the_demo_configuration_is_handed_out_only_where_the_demo_can_run():
    """`execbound-demo`'s configuration for the samples (#247) exists only while every request
    its decide beat sends could be served and decided as it expects: this deployment serves the
    workspace's samples (`available`: it holds the sample key and no configured connector for
    the tenant), the starter is the policy the default space selects and the workspace enforces
    it (`in_force`), the starter's own mapping of the isolation action is live, each of the
    three named targets carries an open incident, and no emergency stop is active (`stopped`).
    Anything else would hand the person a file whose first request is refused or decided
    otherwise, which a refresh and a new download cannot change."""
    tenant = uuid4()

    def configuration(status):
        return samples.demo_configuration(
            status,
            now=DEMO_NOW,
            origin="https://console.example",
            tenant_id=tenant,
            provider_origin="https://endpoint.example",
        )

    ready = _demo_status()
    hosts = by_effect(ready)
    assert samples.demo_targets(ready, now=DEMO_NOW) == {
        "workstation": hosts["allow"],
        "domain_controller": hosts["deny"],
        "production": hosts["require approval"],
    }
    assert configuration(ready) == {
        "workspace": "samples",
        "origin": "https://console.example",
        "tenant_id": str(tenant),
        "providers": {"endpoint": "https://endpoint.example"},
        "targets": {
            **{
                name: {
                    "kind": "hostname",
                    "value": hosts[effect].hostname,
                    "incident_id": str(hosts[effect].incident_id),
                }
                for name, effect in (
                    ("workstation", "allow"),
                    ("domain_controller", "deny"),
                    ("production", "require approval"),
                )
            },
            "pool": [],
        },
    }
    for refused in (
        # No sample key, or a configured connector for this tenant: nothing reaches the samples.
        _demo_status(available=False),
        # A policy a person made decides the samples in the starter's place, or the workspace
        # observes rather than enforces: the decide beat's three outcomes no longer follow.
        _demo_status(in_force=False),
        # The starter names no live mapping of the isolation action the demo sends.
        _demo_status(operation_ref=None),
        _demo_status(operation_ref="sample.contain"),
        # A named target with no open incident, which admission finds no context for.
        _demo_status(closed="allow"),
        _demo_status(closed="deny"),
        _demo_status(closed="require approval"),
        # An emergency stop, under which admission refuses every new request before it reads a
        # fact, and which only an administrator's release ends.
        _demo_status(stopped=True),
        samples.SampleStatus("absent", True, True),
    ):
        assert samples.demo_targets(refused, now=DEMO_NOW) is None
        assert configuration(refused) is None
        # None of these is one a refresh is the way out of.
        assert not samples.demo_needs_refresh(refused, now=DEMO_NOW)
    assert not samples.demo_needs_refresh(ready, now=DEMO_NOW)


@pytest.mark.parametrize(
    "changed", [("allow",), ("require approval",), ("deny",), ("allow", "deny")]
)
def test_sm11_the_demo_configuration_waits_for_a_refresh_once_a_named_target_was_changed(changed):
    """The decide beat sends the workstation isolation first and needs it to execute, and the
    production one to execute once approved, each at the version the samples' facts record. A
    request since the facts were recorded that reached the provider on a named target, such as
    the ones guided setup has the person's own agent make, moved that target past the recorded
    version, so the demo's request on it would end `STALE_AUTHORIZATION`. The configuration is
    then not handed out, and a refresh, which records the targets afresh, is the way back: the
    console says so rather than offer a file whose first run fails. A domain controller the
    starter denies counts too, since the demo needs the samples as their facts record them."""
    used = _demo_status(changed=changed)
    assert samples.demo_targets(used, now=DEMO_NOW) is None
    assert (
        samples.demo_configuration(
            used,
            now=DEMO_NOW,
            origin="https://console.example",
            tenant_id=uuid4(),
            provider_origin="https://endpoint.example",
        )
        is None
    )
    assert samples.demo_needs_refresh(used, now=DEMO_NOW)


def test_sm11_the_demo_configuration_waits_for_a_refresh_once_the_sample_facts_are_stale():
    """The starter keeps each sample fact for an hour, and nothing records them again but a
    refresh: from `stale_at` every request on the samples is refused before any decision with
    `EXECUTION_UNAVAILABLE`, so the decide beat's first would be. The configuration is handed
    out until that very instant and not from it, judged as admission judges a fact against its
    `valid_until`, and a refresh, which records them afresh, is then the way back. Staleness
    is no way out of anything else: samples the demo could not run on for another reason stay
    without a refresh to offer, and so do samples a request still waits on."""
    ready = _demo_status()
    assert ready.stale_at is not None
    before = ready.stale_at - timedelta(microseconds=1)
    assert samples.demo_targets(ready, now=before) is not None
    assert not samples.demo_needs_refresh(ready, now=before)
    for stale in (ready.stale_at, ready.stale_at + timedelta(hours=3)):
        assert samples.demo_targets(ready, now=stale) is None
        assert (
            samples.demo_configuration(
                ready,
                now=stale,
                origin="https://console.example",
                tenant_id=uuid4(),
                provider_origin="https://endpoint.example",
            )
            is None
        )
        assert samples.demo_needs_refresh(ready, now=stale)
        # Stale and changed alike: one refresh answers both.
        assert samples.demo_needs_refresh(_demo_status(changed=("allow",)), now=stale)
        for refused in (
            _demo_status(available=False),
            _demo_status(in_force=False),
            _demo_status(operation_ref=None),
            _demo_status(closed="deny"),
            _demo_status(state="present"),
            _demo_status(stopped=True),
            _demo_status(stopped=True, changed=("allow",)),
        ):
            assert samples.demo_targets(refused, now=stale) is None
            assert not samples.demo_needs_refresh(refused, now=stale)


def test_sm11_the_demo_configuration_waits_while_a_sample_request_is_unresolved():
    """A request on the samples waiting for approval or provider evidence may yet change a
    target the demo names, so the configuration waits for it; and a refresh, which is refused
    while it waits, is not yet the way out, so the console offers neither."""
    for changed in ((), ("allow",)):
        held = _demo_status(state="present", changed=changed)
        assert samples.demo_targets(held, now=DEMO_NOW) is None
        assert not samples.demo_needs_refresh(held, now=DEMO_NOW)


@pytest.mark.parametrize(
    ("origin", "provider_origin", "named"),
    [
        # A public mock is the same mock from any machine, beside either kind of gateway.
        ("https://console.example", "https://endpoint.example", True),
        ("http://127.0.0.1:8080", "https://endpoint.example", True),
        # A loopback mock is the gateway's own view of it, and nothing on the gateway says
        # whether the person's machine reaches the mock at that address. The Community bundle
        # publishes the gateway's port alone, on the host's loopback, and keeps the mock on
        # 127.0.0.1:8001 inside its own network namespace, so a gateway on loopback is no sign
        # either. On the person's machine the address is whatever listens there, and the
        # boundary beat sends agent A's key to every origin `providers` names, so it names none.
        ("http://127.0.0.1:8080", "http://127.0.0.1:8001", False),
        ("http://localhost:8000", "http://[::1]:8001", False),
        ("https://console.example", "http://127.0.0.1:8001", False),
        ("https://console.example", "https://localhost:8443", False),
        ("https://console.example", "http://[::1]:8001", False),
        ("https://console.example", "http://127.8.9.10:8001", False),
    ],
)
def test_sm11_the_demo_configuration_never_names_a_loopback_mock(origin, provider_origin, named):
    document = samples.demo_configuration(
        _demo_status(),
        now=DEMO_NOW,
        origin=origin,
        tenant_id=uuid4(),
        provider_origin=provider_origin,
    )
    assert document is not None
    if named:
        assert document["providers"] == {"endpoint": provider_origin}
    else:
        assert "providers" not in document


def refusal(call, *args, **kwargs) -> str:
    with pytest.raises(samples.SampleError) as refused:
        call(*args, **kwargs)
    return refused.value.code


def state_of(db, tenant):
    with db.transaction(tenant) as conn:
        return samples.status(conn, tenant, available=True)


def removed_as_retired(engine, tenant, bundle):
    """What a removal that retired an unchanged starter leaves: every sample row switched off,
    the bundle retired and no space selecting anything."""
    with engine.begin() as conn:
        fenced(conn, tenant)
        actives = {
            table: set(
                conn.execute(
                    text(f"SELECT active FROM execbound.{table} WHERE tenant_id = :t"),
                    {"t": tenant},
                ).scalars()
            )
            for table in DEACTIVATED
        }
        state = conn.execute(
            text(
                "SELECT state FROM execbound.policy_bundle_lifecycle "
                "WHERE tenant_id = :t AND bundle_id = :b"
            ),
            {"t": tenant, "b": bundle},
        ).scalar_one()
        selections = conn.execute(
            text("SELECT count(*) FROM execbound.space_policy_selection WHERE tenant_id = :t"),
            {"t": tenant},
        ).scalar_one()
    assert actives == {table: {False} for table in DEACTIVATED}
    assert (state, selections) == ("RETIRED", 0)


def assert_removal_events(engine, workspace, installed):
    """The removal and the starter's own lifecycle events, each naming the administrator and
    the credential they acted with."""
    tail = chain(engine, workspace.tenant_id)[-3:]
    assert [event["kind"] for event in tail] == [
        "samples.removed",
        "policy.bundle_deselected",
        "policy.bundle_retired",
    ]
    assert {event["actor_id"] for event in tail} == {workspace.admin.principal_id}
    assert tail[0]["payload"] == {
        "account_id": str(installed.account_id),
        "bundle_id": str(installed.bundle_id),
        "retired": True,
        "actor_credential_id": str(workspace.admin.credential_id),
    }
    assert {event["payload"]["bundle_id"] for event in tail} == {str(installed.bundle_id)}
    # Each names the credential that removed them, as the policy store's own events do.
    assert {event["payload"]["actor_credential_id"] for event in tail} == {
        str(workspace.admin.credential_id)
    }
    assert tail[1]["payload"]["space_id"] == str(workspace.space_id)


@pytest.fixture
def captured():
    """`logging_schema`'s own handler on the `execbound` logger, as `test_community_signup`
    attaches it, so a record is read exactly as an operator would read it."""
    stream = io.StringIO()
    handler = logging_schema.capture_handler(stream)
    logger = logging.getLogger("execbound")
    logger.addHandler(handler)
    try:
        yield stream
    finally:
        logger.removeHandler(handler)


def logged(stream, event):
    """Every record of one event in the captured process log, in order."""
    return [
        record
        for record in (json.loads(line) for line in stream.getvalue().splitlines() if line.strip())
        if record.get("event") == event
    ]


def refusals(stream):
    return logged(stream, "samples.refused")


def wrote(stream, event):
    """What each logged install, removal or refresh says: the resulting state and who acted."""
    return [(record["state"], record["principal_id"]) for record in logged(stream, event)]


def leave_unresolved(db, admin_engine, workspace, installed, stage):
    """One request on the samples left in `stage`, which SM6b and SM9b both need."""
    agent = agent_identity(admin_engine, db, workspace)
    hosts, clock = by_effect(installed), SystemClock()
    if stage == "PENDING_APPROVAL":
        held = admit(db, agent, request_for(hosts["require approval"], "sample-prod"), clock)
        assert held.view.state == "PENDING_APPROVAL"
    else:
        admission = admit(db, agent, request_for(hosts["allow"], "sample-dev"), clock)
        assert admission.ticket is not None
        if stage in {"DISPATCH_COMMITTED", "INDETERMINATE"}:
            take_dispatch(db, admission.ticket, clock)
        if stage == "INDETERMINATE":
            mark_indeterminate(db, admission.ticket, clock)
    if stage in {"ATTEMPTED", "RESERVED"}:
        # Admission commits neither: a request passes through both inside its own transaction
        # and leaves it DISPATCH_COMMITTED. The owner writes one to stand for a request caught
        # there, so every state the definer function calls unresolved is held to the refusal.
        with admin_engine.begin() as conn:
            fenced(conn, workspace.tenant_id)
            conn.execute(
                text("UPDATE execbound.executions SET state = :s WHERE tenant_id = :t"),
                {"s": stage, "t": workspace.tenant_id},
            )
    with admin_engine.begin() as conn:
        fenced(conn, workspace.tenant_id)
        assert (
            conn.execute(
                text("SELECT state FROM execbound.executions WHERE tenant_id = :t"),
                {"t": workspace.tenant_id},
            ).scalar_one()
            == stage
        )


class Later:
    """The system clock moved on by a fixed offset, inside the five minutes the definer
    functions accept between the caller's clock and the database's (`INVALID_CLOCK`)."""

    def __init__(self, seconds: int) -> None:
        self.offset = timedelta(seconds=seconds)

    def now(self) -> datetime:
        return datetime.now(UTC) + self.offset


def test_sm1_install_under_the_hosted_owner_creates_exactly_the_listed_rows(
    stack, tmp_path, captured
):
    engine, db = stack
    made = password_workspace(engine, db, tmp_path)
    admin = made.admin
    tenant = made.tenant_id
    # What the workspace's own making wrote; everything after it is the install's.
    before_install = len(chain(engine, tenant))

    installed = samples.install(db, admin, available=True)

    assert (installed.state, installed.offered, installed.available) == ("removable", False, True)
    assert installed.account_id is not None
    assert installed.bundle_id == samples.starter_bundle_id(tenant, installed.account_id)
    assert {host.provider_id: host.effect for host in installed.hosts} == {
        target.provider_id: target.expected for target in samples.SAMPLE_TARGETS
    }
    assert installed.first_request is None and installed.stale_at is not None
    with engine.begin() as conn:
        fenced(conn, tenant)
        counted = {
            table: conn.execute(
                text(f"SELECT count(*) FROM execbound.{table} WHERE tenant_id = :t"),
                {"t": tenant},
            ).scalar_one()
            for table in (*REGISTRY, *POLICY)
        }
        account = conn.execute(
            text(
                "SELECT account_id, provider, sample, active FROM execbound.connector_accounts "
                "WHERE tenant_id = :t"
            ),
            {"t": tenant},
        ).one()
        lifecycle = conn.execute(
            text(
                "SELECT bundle_id, state FROM execbound.policy_bundle_lifecycle "
                "WHERE tenant_id = :t"
            ),
            {"t": tenant},
        ).one()
        selected = conn.execute(
            text("SELECT bundle_id FROM execbound.space_policy_selection WHERE tenant_id = :t"),
            {"t": tenant},
        ).scalar_one()
        reviewers = set(
            conn.execute(
                text(
                    "SELECT approver_id FROM execbound.approval_scopes "
                    "WHERE tenant_id = :t AND active"
                ),
                {"t": tenant},
            ).scalars()
        )
        versions = set(
            conn.execute(
                text("SELECT version FROM execbound.resources WHERE tenant_id = :t"),
                {"t": tenant},
            ).scalars()
        )
    assert counted == {
        "connector_accounts": 1,
        "context_sources": 2,
        "operation_mappings": 1,
        "canonical_targets": 3,
        "resources": 3,
        "resource_identities": 3,
        "resource_aliases": 6,
        "incidents": 3,
        "approval_scopes": 3,
        "policy_bundle_contents": 1,
        "policy_bundle_lifecycle": 1,
        "space_policy_selection": 1,
    }
    assert tuple(account) == (installed.account_id, "mock_crowdstrike", True, True)
    assert tuple(lifecycle) == (installed.bundle_id, "ACTIVE")
    assert selected == installed.bundle_id
    assert reviewers == {admin.principal_id}
    assert versions == {SAMPLE_RESOURCE_VERSION}
    events = chain(engine, tenant)[before_install:]
    assert [event["kind"] for event in events] == [
        "policy.bundle_created",
        "policy.ruleset_compiled",
        "policy.bundle_validated",
        "policy.bundle_activated",
        "samples.installed",
    ]
    assert all(event["actor_id"] == admin.principal_id for event in events)
    assert events[-1]["payload"]["account_id"] == str(installed.account_id)
    assert events[-1]["payload"]["bundle_id"] == str(installed.bundle_id)
    assert wrote(captured, "samples.installed") == [("removable", str(admin.principal_id))]
    before = rows(engine, tenant)
    assert samples.install(db, admin, available=True) == installed
    assert rows(engine, tenant) == before
    # The second install found the samples present and wrote nothing, so it logs nothing.
    assert wrote(captured, "samples.installed") == [("removable", str(admin.principal_id))]


def test_sm1c_install_and_removal_replay_as_complete_history(db, admin_engine, seeded):
    workspace = empty_workspace(admin_engine, db)
    samples.install(db, workspace.admin, available=True)
    samples.remove(db, workspace.admin, available=True)
    history = export_history(db, workspace.admin, SystemClock())
    report = simulate(verify_export(history, history.head))
    assert report.complete, report.issues


def test_sm1d_a_new_bundle_never_replaces_a_space_that_already_selects_one(
    db, admin_engine, seeded
):
    workspace = empty_workspace(admin_engine, db)
    installed = samples.install(db, workspace.admin, available=True)
    assert installed.account_id is not None
    other = samples.starter_bundle(workspace.tenant_id, installed.account_id).model_copy(
        update={"bundle_id": uuid4()}
    )
    with pytest.raises(PolicyStoreError) as refused:
        with db.transaction(workspace.tenant_id) as conn:
            activate_new_bundle(
                conn, workspace.admin, other, SystemClock(), space=workspace.space_id
            )
    assert refused.value.code == "INVALID_STATE"


def test_sm2_install_is_refused_for_a_policy_a_connection_a_person_and_a_missing_key(
    db, admin_engine, seeded
):
    workspace = empty_workspace(admin_engine, db)
    approver = person(admin_engine, db, workspace)
    assert refusal(samples.install, db, workspace.admin, available=False) == "SAMPLES_UNAVAILABLE"
    assert refusal(samples.install, db, approver, available=True) == "FORBIDDEN"
    assert state_of(db, workspace.tenant_id).offered is True
    select_policy(
        admin_engine, workspace.tenant_id, workspace.space_id, workspace.admin.principal_id
    )
    assert state_of(db, workspace.tenant_id).offered is False
    assert refusal(samples.install, db, workspace.admin, available=True) == "POLICY_PRESENT"

    connected = empty_workspace(admin_engine, db)
    with admin_engine.begin() as conn:
        fenced(conn, connected.tenant_id)
        conn.execute(
            text(
                "INSERT INTO execbound.connector_accounts(tenant_id, account_id, provider, "
                "space_id) VALUES (:t, :a, 'mock_entra', :s)"
            ),
            {"t": connected.tenant_id, "a": uuid4(), "s": connected.space_id},
        )
    assert state_of(db, connected.tenant_id).offered is False
    assert refusal(samples.install, db, connected.admin, available=True) == "ACCOUNT_PRESENT"
    for tenant in (workspace.tenant_id, connected.tenant_id):
        with admin_engine.begin() as conn:
            fenced(conn, tenant)
            assert (
                conn.execute(
                    text(
                        "SELECT count(*) FROM execbound.connector_accounts "
                        "WHERE tenant_id = :t AND sample"
                    ),
                    {"t": tenant},
                ).scalar_one()
                == 0
            )


def test_sm2b_an_administrator_seated_in_a_space_may_neither_add_nor_remove_samples(
    db, admin_engine, seeded
):
    """Samples are the whole workspace's. An ADMIN seated in a space passes the kernel's
    administrator check, which accepts the permission in any scope, and is then refused by the
    definer functions, which ask for a tenant administrator: one with no membership."""
    workspace = empty_workspace(admin_engine, db)
    seated = person(admin_engine, db, workspace, kind="ADMIN")
    with admin_engine.begin() as conn:
        fenced(conn, workspace.tenant_id)
        seat(conn, workspace.tenant_id, workspace.space_id, seated.principal_id, "ADMIN")
    before = rows(admin_engine, workspace.tenant_id)
    assert refusal(samples.install, db, seated, available=True) == "FORBIDDEN"
    assert rows(admin_engine, workspace.tenant_id) == before

    samples.install(db, workspace.admin, available=True)
    before = rows(admin_engine, workspace.tenant_id)
    assert refusal(samples.remove, db, seated, available=True) == "FORBIDDEN"
    assert rows(admin_engine, workspace.tenant_id) == before
    assert state_of(db, workspace.tenant_id).state == "removable"


def test_sm2c_a_fault_is_unavailable_and_its_log_names_the_class_and_never_the_message(
    db, admin_engine, seeded, captured
):
    """A fault's reason is its class name, and for a store's own error also the fixed code it
    carries, which is what tells an operator a ruleset mismatch from a database outage."""
    workspace = empty_workspace(admin_engine, db)
    approver = person(admin_engine, db, workspace)

    def failing(conn):
        raise ValueError("ws-dev-01.sample.invalid is not for the log")

    def mismatched(conn):
        raise PolicyStoreError("RULESET_MISMATCH")

    def unavailable_store(conn):
        raise ExecutionError()

    assert refusal(samples.install, db, approver, available=True) == "FORBIDDEN"
    for check in (failing, mismatched, unavailable_store):
        assert (
            refusal(samples.install, db, workspace.admin, available=True, authority_check=check)
            == "UNAVAILABLE"
        ), check.__name__
    forbidden, *unavailable = refusals(captured)
    assert (forbidden["code"], "reason" in forbidden) == ("FORBIDDEN", False)
    assert [(record["code"], record["reason"]) for record in unavailable] == [
        ("UNAVAILABLE", "ValueError"),
        ("UNAVAILABLE", "PolicyStoreError:RULESET_MISMATCH"),
        ("UNAVAILABLE", "ExecutionError:EXECUTION_UNAVAILABLE"),
    ]
    assert {record["principal_id"] for record in unavailable} == {str(workspace.admin.principal_id)}
    for message in ("sample.invalid", "Policy store unavailable", "Execution unavailable"):
        assert message not in captured.getvalue(), message
    assert state_of(db, workspace.tenant_id).state == "absent"


def test_sm6_removal_keeps_history_retires_the_unchanged_starter_and_offers_install_again(
    db, admin_engine, seeded, captured
):
    workspace = empty_workspace(admin_engine, db)
    installed = samples.install(db, workspace.admin, available=True)
    agent = agent_identity(admin_engine, db, workspace)
    denied = admit(db, agent, request_for(by_effect(installed)["deny"], "sample-dc"), SystemClock())
    assert denied.view.state == "DENIED" and denied.ticket is None
    before = rows(admin_engine, workspace.tenant_id)

    removed = samples.remove(db, workspace.admin, available=True)

    assert (removed.state, removed.offered, removed.account_id) == ("absent", True, None)
    after = rows(admin_engine, workspace.tenant_id)
    for table in REGISTRY:
        assert len(after[table]) == len(before[table]), table
    removed_as_retired(admin_engine, workspace.tenant_id, installed.bundle_id)
    with admin_engine.begin() as conn:
        fenced(conn, workspace.tenant_id)
        assert conn.execute(
            text("SELECT state FROM execbound.executions WHERE tenant_id = :t"),
            {"t": workspace.tenant_id},
        ).scalars().all() == ["DENIED"]
    assert_removal_events(admin_engine, workspace, installed)
    removal = [("absent", str(workspace.admin.principal_id))]
    assert wrote(captured, "samples.removed") == removal
    # With nothing left to remove, a removal answers with the status, writes nothing and so
    # logs nothing: the process log never reports a removal that did not happen.
    settled = rows(admin_engine, workspace.tenant_id)
    assert samples.remove(db, workspace.admin, available=True) == removed
    assert rows(admin_engine, workspace.tenant_id) == settled
    assert wrote(captured, "samples.removed") == removal

    again = samples.install(db, workspace.admin, available=True)
    assert again.state == "removable"
    assert again.account_id not in (None, installed.account_id)
    with admin_engine.begin() as conn:
        fenced(conn, workspace.tenant_id)
        assert conn.execute(
            text("SELECT account_id FROM execbound.operation_mappings WHERE tenant_id = :t"),
            {"t": workspace.tenant_id},
        ).scalars().all() == [again.account_id]
    # Every account ever marked sample stays one, so the policy page can badge both starters.
    with db.transaction(workspace.tenant_id) as conn:
        assert samples.sample_accounts(conn, workspace.tenant_id) == {
            installed.account_id,
            again.account_id,
        }
        assert samples.sample_bundles(conn, workspace.tenant_id) == {
            installed.bundle_id,
            again.bundle_id,
        }


@pytest.mark.parametrize("stage", UNRESOLVED)
def test_sm6b_removal_is_refused_while_a_sample_request_is_unresolved(
    db, admin_engine, seeded, stage
):
    """Every state the kernel calls unresolved, read from its own list, so a state added to
    `models.UNRESOLVED` and missed by admission or by the definer function's literal fails
    here instead of letting a removal strand a request in it."""
    workspace = empty_workspace(admin_engine, db)
    installed = samples.install(db, workspace.admin, available=True)
    leave_unresolved(db, admin_engine, workspace, installed, stage)
    before = rows(admin_engine, workspace.tenant_id)
    assert refusal(samples.remove, db, workspace.admin, available=True) == "SAMPLES_BUSY"
    assert rows(admin_engine, workspace.tenant_id) == before
    assert state_of(db, workspace.tenant_id).state == "present"


# The states a request on a sample target may have changed it at the provider in, written out
# here rather than read from `samples`, so a state dropped from the status's own list fails: it
# executed, or was dispatched and is not settled, or was settled on somebody's word alone, which
# leaves whether the vendor acted not established. Every other state reached no provider, or
# reached it and was verified not to have acted.
MAY_HAVE_CHANGED = frozenset(
    {"EXECUTED", "DISPATCH_COMMITTED", "INDETERMINATE", "FAILED_EFFECT_UNKNOWN"}
)


@pytest.mark.parametrize("state", get_args(ExecutionState))
def test_sm11_a_sample_request_holds_the_demo_back_by_what_it_may_have_changed(
    db, admin_engine, seeded, state
):
    """The status reads from the executions themselves which named targets a request since
    the facts were recorded may have changed at the provider (SM11, #247), and the demo's
    configuration waits for a refresh once one has: the demo's own isolation of that target
    would find it past the version the facts record and end `STALE_AUTHORIZATION`. Every state
    the kernel has is held to it here on one admitted request on the sample workstation, the
    owner writing each state as SM6b does for those admission passes through, so a state no
    sample request reaches through a command today, `FAILED_EFFECT_UNKNOWN` among them, is
    held to it too. A state that changed nothing leaves the configuration offered, and an
    unresolved one holds it back with no refresh to offer, since a refresh waits for it."""
    workspace = empty_workspace(admin_engine, db)
    installed = samples.install(db, workspace.admin, available=True)
    workstation = by_effect(installed)["allow"]
    agent = agent_identity(admin_engine, db, workspace)
    admission = admit(db, agent, request_for(workstation, "sample-dev"), SystemClock())
    assert admission.ticket is not None
    with admin_engine.begin() as conn:
        fenced(conn, workspace.tenant_id)
        conn.execute(
            text("UPDATE execbound.executions SET state = :s WHERE tenant_id = :t"),
            {"s": state, "t": workspace.tenant_id},
        )
    status = state_of(db, workspace.tenant_id)
    now = datetime.now(UTC)
    changed, unresolved = state in MAY_HAVE_CHANGED, state in UNRESOLVED
    assert status.changed == (frozenset({workstation.provider_id}) if changed else frozenset())
    assert status.state == ("present" if unresolved else "removable")
    assert (samples.demo_targets(status, now=now) is not None) == (not changed and not unresolved)
    assert samples.demo_needs_refresh(status, now=now) == (changed and not unresolved)


def test_sm6c_a_policy_the_person_activated_stays_and_samples_are_not_offered_again(
    db, admin_engine, seeded
):
    workspace = empty_workspace(admin_engine, db)
    installed = samples.install(db, workspace.admin, available=True)
    assert installed.account_id is not None
    edited = samples.starter_bundle(workspace.tenant_id, installed.account_id).model_copy(
        update={"bundle_id": uuid4()}
    )
    create_bundle(db, workspace.admin, edited)
    validate_bundle(db, workspace.admin, edited.bundle_id)
    activate_bundle(db, workspace.admin, edited.bundle_id)

    removed = samples.remove(db, workspace.admin, available=True)

    assert (removed.state, removed.offered) == ("absent", False)
    with admin_engine.begin() as conn:
        fenced(conn, workspace.tenant_id)
        states = dict(
            conn.execute(
                text(
                    "SELECT bundle_id, state FROM execbound.policy_bundle_lifecycle "
                    "WHERE tenant_id = :t"
                ),
                {"t": workspace.tenant_id},
            ).all()
        )
        selected = conn.execute(
            text("SELECT bundle_id FROM execbound.space_policy_selection WHERE tenant_id = :t"),
            {"t": workspace.tenant_id},
        ).scalar_one()
    assert states == {installed.bundle_id: "VALIDATED", edited.bundle_id: "ACTIVE"}
    assert selected == edited.bundle_id
    last = chain(admin_engine, workspace.tenant_id)[-1]
    assert (last["kind"], last["payload"]["retired"]) == ("samples.removed", False)


def test_sm6d_removal_from_a_workspace_that_never_had_samples_writes_nothing(
    db, admin_engine, seeded, captured
):
    workspace = empty_workspace(admin_engine, db)
    before = rows(admin_engine, workspace.tenant_id)

    removed = samples.remove(db, workspace.admin, available=True)

    assert removed == samples.SampleStatus("absent", True, True)
    after = rows(admin_engine, workspace.tenant_id)
    # The fence row every tenant transaction upserts is the only thing that may appear.
    del before["tenant_policy_control"], after["tenant_policy_control"]
    assert after == before
    # Nothing was removed, so the process log says nothing was.
    assert logged(captured, "samples.removed") == []


def test_sm6e_removal_under_the_hosted_owner_retires_the_starter_and_names_the_administrator(
    stack, tmp_path
):
    engine, db = stack
    made = password_workspace(engine, db, tmp_path)
    installed = samples.install(db, made.admin, available=True)
    before = rows(engine, made.tenant_id)

    removed = samples.remove(db, made.admin, available=True)

    assert (removed.state, removed.offered, removed.account_id) == ("absent", True, None)
    after = rows(engine, made.tenant_id)
    for table in REGISTRY:
        assert len(after[table]) == len(before[table]), table
    removed_as_retired(engine, made.tenant_id, installed.bundle_id)
    assert_removal_events(engine, made, installed)


def test_sm9_refresh_records_the_samples_again_in_one_transaction_with_both_audits(
    db, admin_engine, seeded, captured
):
    """A refresh (#545) is a removal and an install in the one fenced transaction each
    takes alone: the same three targets with new canonical ids and incidents and facts recorded
    now, the old starter retired and a new one selected, the first request counted afresh and
    every request already made kept. Review returns to the administrator who refreshed alone,
    exactly as an install gives it to the one who installed: the installer's scopes and another
    reviewer's are switched off with the old targets. The chain holds the removal's three events
    and the install's five, each naming the refreshing administrator and their credential, the
    log says `samples.refreshed`, and replay reads the whole history as complete."""
    workspace = empty_workspace(admin_engine, db)
    installed = samples.install(db, workspace.admin, available=True)
    refresher = person(admin_engine, db, workspace, kind="ADMIN")
    reviewer = person(admin_engine, db, workspace)
    denied_host = by_effect(installed)["deny"]
    with admin_engine.begin() as conn:
        fenced(conn, workspace.tenant_id)
        conn.execute(
            text(
                "INSERT INTO execbound.approval_scopes(tenant_id, approver_id, "
                "canonical_target_id, action, space_id) VALUES (:t, :p, :c, "
                "'endpoint.isolate', :s)"
            ),
            {
                "t": workspace.tenant_id,
                "p": reviewer.principal_id,
                "c": denied_host.canonical_target_id,
                "s": workspace.space_id,
            },
        )
    agent = agent_identity(admin_engine, db, workspace)
    denied = admit(db, agent, request_for(denied_host, "sample-dc"), SystemClock())
    assert denied.view.state == "DENIED"
    before = len(chain(admin_engine, workspace.tenant_id))

    fresh = samples.refresh(db, refresher, available=True)

    assert (fresh.state, fresh.offered, fresh.first_request) == ("removable", False, None)
    assert fresh.account_id not in (None, installed.account_id)
    assert fresh.bundle_id == samples.starter_bundle_id(workspace.tenant_id, fresh.account_id)
    assert installed.observed_at is not None and fresh.observed_at is not None
    assert fresh.observed_at >= installed.observed_at
    assert [host.hostname for host in fresh.hosts] == [host.hostname for host in installed.hosts]
    assert {host.provider_id: host.effect for host in fresh.hosts} == {
        target.provider_id: target.expected for target in samples.SAMPLE_TARGETS
    }
    for field in ("incident_id", "canonical_target_id"):
        old = {getattr(host, field) for host in installed.hosts}
        assert old.isdisjoint(getattr(host, field) for host in fresh.hosts), field
    events = chain(admin_engine, workspace.tenant_id)[before:]
    assert [event["kind"] for event in events] == [
        "samples.removed",
        "policy.bundle_deselected",
        "policy.bundle_retired",
        "policy.bundle_created",
        "policy.ruleset_compiled",
        "policy.bundle_validated",
        "policy.bundle_activated",
        "samples.installed",
    ]
    assert {event["actor_id"] for event in events} == {refresher.principal_id}
    assert {event["payload"]["actor_credential_id"] for event in events} == {
        str(refresher.credential_id)
    }
    assert events[0]["payload"]["account_id"] == str(installed.account_id)
    assert events[0]["payload"]["retired"] is True
    assert events[-1]["payload"]["account_id"] == str(fresh.account_id)
    assert events[-1]["payload"]["bundle_id"] == str(fresh.bundle_id)
    params = {"t": workspace.tenant_id}
    with admin_engine.begin() as conn:
        fenced(conn, workspace.tenant_id)
        accounts = dict(
            conn.execute(
                text(
                    "SELECT account_id, active FROM execbound.connector_accounts "
                    "WHERE tenant_id = :t"
                ),
                params,
            ).all()
        )
        mapped = (
            conn.execute(
                text(
                    "SELECT account_id FROM execbound.operation_mappings "
                    "WHERE tenant_id = :t AND active"
                ),
                params,
            )
            .scalars()
            .all()
        )
        states = dict(
            conn.execute(
                text(
                    "SELECT bundle_id, state FROM execbound.policy_bundle_lifecycle "
                    "WHERE tenant_id = :t"
                ),
                params,
            ).all()
        )
        selected = conn.execute(
            text("SELECT bundle_id FROM execbound.space_policy_selection WHERE tenant_id = :t"),
            params,
        ).scalar_one()
        scopes = {
            (row[0], row[1]): row[2]
            for row in conn.execute(
                text(
                    "SELECT approver_id, active, count(*) FROM execbound.approval_scopes "
                    "WHERE tenant_id = :t GROUP BY approver_id, active"
                ),
                params,
            )
        }
        executions = conn.execute(
            text("SELECT execution_id, state FROM execbound.executions WHERE tenant_id = :t"),
            params,
        ).all()
    assert accounts == {installed.account_id: False, fresh.account_id: True}
    assert mapped == [fresh.account_id]
    assert states == {installed.bundle_id: "RETIRED", fresh.bundle_id: "ACTIVE"}
    assert selected == fresh.bundle_id
    assert scopes == {
        (workspace.admin.principal_id, False): 3,
        (reviewer.principal_id, False): 1,
        (refresher.principal_id, True): 3,
    }
    assert [tuple(row) for row in executions] == [(denied.view.execution_id, "DENIED")]
    assert wrote(captured, "samples.refreshed") == [("removable", str(refresher.principal_id))]
    history = export_history(db, workspace.admin, SystemClock())
    report = simulate(verify_export(history, history.head))
    assert report.complete, report.issues


@pytest.mark.parametrize("stage", UNRESOLVED)
def test_sm9b_refresh_is_refused_while_a_sample_request_is_unresolved(
    db, admin_engine, seeded, stage
):
    """A refresh removes first, so it is refused exactly where a removal is (SM6b): in every
    state the kernel calls unresolved, with nothing changed."""
    workspace = empty_workspace(admin_engine, db)
    installed = samples.install(db, workspace.admin, available=True)
    leave_unresolved(db, admin_engine, workspace, installed, stage)
    before = rows(admin_engine, workspace.tenant_id)
    assert refusal(samples.refresh, db, workspace.admin, available=True) == "SAMPLES_BUSY"
    assert rows(admin_engine, workspace.tenant_id) == before
    assert state_of(db, workspace.tenant_id).state == "present"


def test_sm9c_a_refresh_is_refused_rather_than_break_a_persons_policy_or_connection(
    db, admin_engine, seeded
):
    """A policy a person made from the starter names the sample account's mapping, and a
    refresh switches that account off, which would leave the policy unable to validate or
    authorize anything. So a refresh is refused `POLICY_PRESENT`, before anything is removed,
    while any bundle other than the starter that is not retired names the sample account: a
    validated copy that was never activated, and the same copy once it is. A connection the
    person added is refused by the install step (`ACCOUNT_PRESENT`) after the removal has run,
    and the removal rolls back with it. Every row is as it was each time."""
    workspace = empty_workspace(admin_engine, db)
    installed = samples.install(db, workspace.admin, available=True)
    assert installed.account_id is not None
    copy = samples.starter_bundle(workspace.tenant_id, installed.account_id).model_copy(
        update={"bundle_id": uuid4()}
    )
    create_bundle(db, workspace.admin, copy)
    validate_bundle(db, workspace.admin, copy.bundle_id)
    before = rows(admin_engine, workspace.tenant_id)

    assert refusal(samples.refresh, db, workspace.admin, available=True) == "POLICY_PRESENT"

    assert rows(admin_engine, workspace.tenant_id) == before
    # The copy still stands on the sample account's mapping, so it can still be made live;
    # after a refresh that went through, this refused `INVALID_COMPONENT`.
    activate_bundle(db, workspace.admin, copy.bundle_id)
    before = rows(admin_engine, workspace.tenant_id)
    assert refusal(samples.refresh, db, workspace.admin, available=True) == "POLICY_PRESENT"
    assert rows(admin_engine, workspace.tenant_id) == before
    assert state_of(db, workspace.tenant_id).account_id == installed.account_id

    connected = empty_workspace(admin_engine, db)
    samples.install(db, connected.admin, available=True)
    with admin_engine.begin() as conn:
        fenced(conn, connected.tenant_id)
        conn.execute(
            text(
                "INSERT INTO execbound.connector_accounts(tenant_id, account_id, provider, "
                "space_id) VALUES (:t, :a, 'mock_entra', :s)"
            ),
            {"t": connected.tenant_id, "a": uuid4(), "s": connected.space_id},
        )
    before = rows(admin_engine, connected.tenant_id)

    assert refusal(samples.refresh, db, connected.admin, available=True) == "ACCOUNT_PRESENT"

    assert rows(admin_engine, connected.tenant_id) == before


def test_sm9d_a_lapsed_approval_holds_the_refresh_until_it_is_ended(db, admin_engine, seeded):
    """An approval past its deadline leaves its request `PENDING_APPROVAL` until something
    ends it, which the recovery run does every fifteen minutes, so a refresh in between is
    refused `SAMPLES_BUSY` as for any unresolved request; once it is ended the refresh goes
    through. The workspace's default deadline is two minutes, and the clock is 200 seconds
    on."""
    workspace = empty_workspace(admin_engine, db)
    installed = samples.install(db, workspace.admin, available=True)
    agent = agent_identity(admin_engine, db, workspace)
    held = admit(
        db,
        agent,
        request_for(by_effect(installed)["require approval"], "sample-prod"),
        SystemClock(),
    )
    assert held.view.state == "PENDING_APPROVAL"
    later = Later(200)
    before = rows(admin_engine, workspace.tenant_id)

    assert (
        refusal(samples.refresh, db, workspace.admin, available=True, clock=later) == "SAMPLES_BUSY"
    )
    assert rows(admin_engine, workspace.tenant_id) == before

    assert expire_approval(db, workspace.admin, held.view.execution_id, later) is True
    fresh = samples.refresh(db, workspace.admin, available=True)
    assert fresh.state == "removable" and fresh.account_id != installed.account_id


@pytest.mark.parametrize("first", ["request", "refresh"])
def test_sm9e_a_refresh_and_a_held_request_on_the_fence_never_strand_the_request(
    db, admin_engine, seeded, first
):
    """Admission and a refresh each take the tenant fence before reading anything, so whichever
    has it first finishes before the other reads. A holder takes the fence, the first call and
    then the second are left waiting on it in that order, and the holder lets go. Request
    first: it is held for approval, and the refresh finds it pending and refuses. Refresh
    first: the request names an incident the refresh replaced and is refused before any plan.
    Either way no unresolved request is left on a switched-off account."""
    workspace = empty_workspace(admin_engine, db)
    installed = samples.install(db, workspace.admin, available=True)
    agent = agent_identity(admin_engine, db, workspace)
    host = by_effect(installed)["require approval"]

    def asking():
        try:
            return admit(db, agent, request_for(host, "sample-race"), SystemClock()).view.state
        except ExecutionError as refused:
            return refused.code

    def refreshing():
        try:
            return samples.refresh(db, workspace.admin, available=True).state
        except samples.SampleError as refused:
            return refused.code

    calls = (asking, refreshing) if first == "request" else (refreshing, asking)
    with admin_engine.connect() as holder:
        holding = holder.begin()
        fenced(holder, workspace.tenant_id)
        holder.execute(
            text("SELECT 1 FROM execbound.tenant_policy_control WHERE tenant_id = :t FOR UPDATE"),
            {"t": workspace.tenant_id},
        )
        with ThreadPoolExecutor(max_workers=2) as pool:
            try:
                earlier = pool.submit(calls[0])
                blocked_on_a_lock(admin_engine)
                later = pool.submit(calls[1])
                blocked_on_a_lock(admin_engine, waiting=2)
            finally:
                holding.commit()
            outcome = (earlier.result(timeout=30), later.result(timeout=30))
    expected = {
        "request": ("PENDING_APPROVAL", "SAMPLES_BUSY"),
        "refresh": ("removable", "EXECUTION_UNAVAILABLE"),
    }
    assert outcome == expected[first]
    with admin_engine.begin() as conn:
        fenced(conn, workspace.tenant_id)
        stranded = conn.execute(
            text(
                "SELECT count(*) FROM execbound.executions e "
                "JOIN execbound.connector_accounts a ON a.tenant_id = e.tenant_id "
                "AND CAST(a.account_id AS text) = e.frozen #>> '{intent,account_id}' "
                "WHERE e.tenant_id = :t AND e.state = ANY(CAST(:states AS text[])) "
                "AND NOT a.active"
            ),
            {"t": workspace.tenant_id, "states": list(UNRESOLVED)},
        ).scalar_one()
    assert stranded == 0


def test_sm9f_stale_sample_facts_are_refused_before_any_plan_until_a_refresh(
    db, admin_engine, seeded
):
    """The starter ruleset keeps a fact for an hour (`max_age_seconds` 3600), so after an hour
    every sample request is refused before any plan: the agent is answered
    `EXECUTION_UNAVAILABLE` and no execution is written. A refresh records the facts again: the
    request with the new incident is admitted, and the one naming the replaced incident is
    refused."""
    workspace = empty_workspace(admin_engine, db)
    installed = samples.install(db, workspace.admin, available=True)
    with admin_engine.begin() as conn:
        fenced(conn, workspace.tenant_id)
        for table in ("resources", "incidents"):
            conn.execute(
                text(
                    f"UPDATE execbound.{table} SET observed_at = observed_at - interval '2 hours' "
                    "WHERE tenant_id = :t"
                ),
                {"t": workspace.tenant_id},
            )
    stale = state_of(db, workspace.tenant_id).stale_at
    assert stale is not None and stale < datetime.now(UTC)
    agent = agent_identity(admin_engine, db, workspace)
    allowed = by_effect(installed)["allow"]
    with pytest.raises(ExecutionError) as refused:
        admit(db, agent, request_for(allowed, "sample-stale"), SystemClock())
    assert refused.value.code == "EXECUTION_UNAVAILABLE"
    with admin_engine.begin() as conn:
        fenced(conn, workspace.tenant_id)
        assert (
            conn.execute(
                text("SELECT count(*) FROM execbound.executions WHERE tenant_id = :t"),
                {"t": workspace.tenant_id},
            ).scalar_one()
            == 0
        )

    fresh = samples.refresh(db, workspace.admin, available=True)

    assert fresh.stale_at is not None and fresh.stale_at > datetime.now(UTC)
    with pytest.raises(ExecutionError) as replaced:
        admit(db, agent, request_for(allowed, "sample-old-incident"), SystemClock())
    assert replaced.value.code == "EXECUTION_UNAVAILABLE"
    admitted = admit(
        db, agent, request_for(by_effect(fresh)["allow"], "sample-fresh"), SystemClock()
    )
    assert admitted.ticket is not None


def test_sm9g_refresh_refuses_whom_install_refuses_and_writes_nothing_without_samples(
    db, admin_engine, seeded, captured
):
    """With no samples a refresh answers the status and writes nothing, as a removal does.
    Without a sample key it is refused `SAMPLES_UNAVAILABLE`, as an install is, and an approver
    and an administrator seated in a space are refused `FORBIDDEN`, changing nothing. A copy of
    the starter stands meanwhile, which answers a tenant administrator `POLICY_PRESENT`: the
    seated administrator is refused before the refresh reads it, as the definer functions would
    refuse them, so the answer never tells them whether a policy names the samples."""
    workspace = empty_workspace(admin_engine, db)
    approver = person(admin_engine, db, workspace)
    before = rows(admin_engine, workspace.tenant_id)
    assert samples.refresh(db, workspace.admin, available=True) == samples.SampleStatus(
        "absent", True, True
    )
    after = rows(admin_engine, workspace.tenant_id)
    # The fence row every tenant transaction upserts is the only thing that may appear.
    del before["tenant_policy_control"], after["tenant_policy_control"]
    assert after == before
    # Nothing was refreshed, so the process log says nothing was.
    assert logged(captured, "samples.refreshed") == []

    installed = samples.install(db, workspace.admin, available=True)
    assert installed.account_id is not None
    seated = person(admin_engine, db, workspace, kind="ADMIN")
    with admin_engine.begin() as conn:
        fenced(conn, workspace.tenant_id)
        seat(conn, workspace.tenant_id, workspace.space_id, seated.principal_id, "ADMIN")
    copy = samples.starter_bundle(workspace.tenant_id, installed.account_id).model_copy(
        update={"bundle_id": uuid4()}
    )
    create_bundle(db, workspace.admin, copy)
    before = rows(admin_engine, workspace.tenant_id)
    assert refusal(samples.refresh, db, workspace.admin, available=False) == "SAMPLES_UNAVAILABLE"
    assert refusal(samples.refresh, db, approver, available=True) == "FORBIDDEN"
    assert refusal(samples.refresh, db, seated, available=True) == "FORBIDDEN"
    assert refusal(samples.refresh, db, workspace.admin, available=True) == "POLICY_PRESENT"
    assert rows(admin_engine, workspace.tenant_id) == before


def test_a_refresh_whose_removal_finds_the_samples_already_gone_is_refused_and_writes_nothing(
    db, admin_engine, seeded, captured, monkeypatch
):
    """A refresh reads the active sample account under the tenant fence, so the removal that
    follows cannot find it switched off: `samples_remove` answering `ABSENT` there is
    unreachable. Were it reached, the install would go ahead over a removal this refresh never
    made or recorded. The test reaches it by switching the account off itself, inside the
    refresh's own transaction just before the removal, as another removal would have done
    without the fence: the refresh is refused `UNAVAILABLE`, every row is as it was, the old
    samples stand and nothing is logged as refreshed."""
    workspace = empty_workspace(admin_engine, db)
    installed = samples.install(db, workspace.admin, available=True)
    assert installed.account_id is not None
    before = rows(admin_engine, workspace.tenant_id)
    remove_rows = samples._remove_rows

    def removed_first(conn, identity, account, now):
        samples._call(
            conn,
            "SELECT execbound.samples_remove(:actor, :account, :bundle, :now)",
            {
                "actor": identity.principal_id,
                "account": account,
                "bundle": samples.starter_bundle_id(identity.tenant_id, account),
                "now": now,
            },
        )
        removed = remove_rows(conn, identity, account, now)
        # The definer function's `ABSENT`: the account is no longer an active sample one.
        assert removed is False
        return removed

    monkeypatch.setattr(samples, "_remove_rows", removed_first)

    assert refusal(samples.refresh, db, workspace.admin, available=True) == "UNAVAILABLE"

    assert rows(admin_engine, workspace.tenant_id) == before
    assert state_of(db, workspace.tenant_id).account_id == installed.account_id
    assert logged(captured, "samples.refreshed") == []
    assert [record["code"] for record in refusals(captured)] == ["UNAVAILABLE"]


def test_sm9h_a_starter_copy_created_while_a_refresh_waits_on_the_fence_holds_it_off(
    db, admin_engine, seeded
):
    """The refresh reads for a person's policy under the tenant fence it takes first. The
    definer functions take the fence as well, but only after that read, so it is the refresh's
    own fence that orders the read against a person creating a copy of the starter. A holder
    takes the fence, the creation and then the refresh are left waiting on it in that order, and
    the holder lets go: the copy is made a draft, the refresh finds it and is refused
    `POLICY_PRESENT`, and the copy still validates over the sample account. Only a creation can
    catch this: once a draft exists, validating or activating it cannot change the answer."""
    workspace = empty_workspace(admin_engine, db)
    installed = samples.install(db, workspace.admin, available=True)
    assert installed.account_id is not None
    copy = samples.starter_bundle(workspace.tenant_id, installed.account_id).model_copy(
        update={"bundle_id": uuid4()}
    )

    def creating():
        return create_bundle(db, workspace.admin, copy).state

    def refreshing():
        try:
            return samples.refresh(db, workspace.admin, available=True).state
        except samples.SampleError as refused:
            return refused.code

    with admin_engine.connect() as holder:
        holding = holder.begin()
        fenced(holder, workspace.tenant_id)
        holder.execute(
            text("SELECT 1 FROM execbound.tenant_policy_control WHERE tenant_id = :t FOR UPDATE"),
            {"t": workspace.tenant_id},
        )
        with ThreadPoolExecutor(max_workers=2) as pool:
            try:
                created = pool.submit(creating)
                blocked_on_a_lock(admin_engine)
                refreshed = pool.submit(refreshing)
                blocked_on_a_lock(admin_engine, waiting=2)
            finally:
                holding.commit()
            outcome = (created.result(timeout=30), refreshed.result(timeout=30))
    assert outcome == ("DRAFT", "POLICY_PRESENT")
    assert validate_bundle(db, workspace.admin, copy.bundle_id).state == "VALIDATED"
    assert state_of(db, workspace.tenant_id).account_id == installed.account_id


def test_sm9i_a_refresh_is_refused_while_a_second_space_selects_the_starter(
    db, admin_engine, seeded
):
    """A removal takes the unchanged starter out of every space that selects it, and an install
    makes the new one live in the default space alone. So while a space other than the default
    one selects the starter, a refresh is refused `POLICY_PRESENT` before anything is removed:
    going through, it left that space selecting nothing and its agents refused
    `NO_ACTIVE_BUNDLE`. Every row is as it was, and both spaces still select the starter."""
    workspace = empty_workspace(admin_engine, db)
    installed = samples.install(db, workspace.admin, available=True)
    with admin_engine.begin() as conn:
        fenced(conn, workspace.tenant_id)
        second = make_space(conn, workspace.tenant_id, "Second")
    activate_bundle(db, workspace.admin, installed.bundle_id, space=second)
    before = rows(admin_engine, workspace.tenant_id)

    assert refusal(samples.refresh, db, workspace.admin, available=True) == "POLICY_PRESENT"

    assert rows(admin_engine, workspace.tenant_id) == before
    with admin_engine.begin() as conn:
        fenced(conn, workspace.tenant_id)
        selections = set(
            conn.execute(
                text(
                    "SELECT space_id, bundle_id FROM execbound.space_policy_selection "
                    "WHERE tenant_id = :t"
                ),
                {"t": workspace.tenant_id},
            ).all()
        )
    assert selections == {
        (workspace.space_id, installed.bundle_id),
        (second, installed.bundle_id),
    }
