# SPDX-License-Identifier: AGPL-3.0-only
"""Shared helpers for the signal tests: an owner-inserted source row and a direct admission."""

import json
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.engine import Connection

from execbound.db import Database
from execbound.policy.models import BundleContent, Condition, MappingRef, Rule, Ruleset
from execbound.policy.rulesets import ruleset_bundle
from execbound.policy.store import activate_bundle, create_bundle, validate_bundle
from execbound.provisioning import create_signal_source
from execbound.signals.models import SignalMapping, SignalThreshold
from execbound.signals.tokens import digest, new_token

PRODUCER = "execbound-mde-producer"
VERSION = "0.1.0"
CAPABILITY = "resource_compromise.v1"


def default_space(conn: Connection, tenant: UUID) -> UUID:
    return conn.execute(
        text(
            "SELECT space_id FROM execbound.spaces WHERE tenant_id=:t "
            "ORDER BY created_at, space_id LIMIT 1"
        ),
        {"t": tenant},
    ).scalar_one()


_ARRAYS = {"capabilities": "text[]", "subject_kinds": "text[]", "principal_ids": "uuid[]"}


def insert_source(
    conn: Connection, tenant: UUID, actor: UUID, now: datetime, **changes: Any
) -> tuple[UUID, str]:
    """A source row written as the owner, for tests that must not depend on the command.

    `changes` overrides any default column or adds any other column of the table.
    """
    source = changes.pop("source_id", uuid4())
    token, _ = new_token(tenant, source)
    row: dict[str, Any] = {
        "tenant_id": tenant,
        "source_id": source,
        "space_id": changes.pop("space_id", None) or default_space(conn, tenant),
        "offered_tenant_wide": False,
        "label": "MDE lab",
        "producer_name": PRODUCER,
        "producer_version_min": "0.1.0",
        "producer_version_max": "0.9.9",
        "capabilities": [CAPABILITY],
        "subject_kinds": ["resource"],
        "principal_ids": [str(actor)],
        "principal_group_id": None,
        "placement": "out_of_process",
        "input_path": "independent",
        "attests_liveness": False,
        "token_hash": digest(token),
        "created_at": now - timedelta(minutes=1),
        "created_by": actor,
        "expires_at": now + timedelta(hours=8),
        "rate_window_at": now - timedelta(minutes=1),
    }
    row.update(changes)
    # Any column may be overridden or added (a rotation's or a revocation's, say); the arrays
    # are cast because a driver list carries no element type.
    columns = ", ".join(row)
    values = ", ".join(
        f"CAST(:{name} AS {_ARRAYS[name]})" if name in _ARRAYS else f":{name}" for name in row
    )
    conn.execute(text(f"INSERT INTO execbound.signal_sources ({columns}) VALUES ({values})"), row)
    return source, token


def signal_fields(account: UUID, now: datetime, **changes: Any) -> dict[str, Any]:
    """The admission arguments for one resource-subject record; `changes` overrides any."""
    fields: dict[str, Any] = {
        "event_id": f"device-01:{int(now.timestamp())}",
        "record_digest": "a" * 64,
        "producer_name": PRODUCER,
        "producer_version": VERSION,
        "capability": CAPABILITY,
        "verdict": "Medium",
        "confidence": 1000,
        "severity": None,
        "subject_kind": "resource",
        "subject_account": account,
        "subject_provider": "mock_crowdstrike",
        "subject_resource_type": "endpoint",
        "subject_provider_id": "device-01",
        "action": None,
        "request_reference": None,
        "observed_at": now,
        "expires_at": None,
        "attributes": {},
        "evidence_ref": None,
        "evidence_digest": None,
    }
    fields.update(changes)
    return fields


ADMIT = text(
    "SELECT execbound.signal_admit(:source, :token_hash, :now, :event_id, :record_digest, "
    ":producer_name, :producer_version, :capability, :verdict, :confidence, :severity, "
    ":subject_kind, :subject_account, :subject_provider, :subject_resource_type, "
    ":subject_provider_id, :action, :request_reference, :observed_at, :expires_at, "
    "CAST(:attributes AS jsonb), :evidence_ref, :evidence_digest)"
)


def admit_params(source: UUID, token: str, now: datetime, **fields: Any) -> dict[str, Any]:
    """`ADMIT`'s parameters for one call, for a test that holds its own transaction open."""
    params = {"source": source, "token_hash": digest(token), "now": now, **fields}
    params["attributes"] = json.dumps(params["attributes"])
    return params


def admit_raw(
    db: Database, tenant: UUID, source: UUID, token: str, now: datetime, **fields: Any
) -> dict[str, Any]:
    """Call the fenced writer as the runtime role, the way the intake does."""
    with db.transaction(tenant) as conn:
        return conn.execute(ADMIT, admit_params(source, token, now, **fields)).scalar_one()


V2 = "endpoint-isolation.v2"
# The verdict table the Defender for Endpoint producer is mapped with (#478), as
# `docs/SIGNALS.md` shows it.
MDE_THRESHOLDS = (
    SignalThreshold(verdict="None", value="no_detection"),
    SignalThreshold(verdict="Informational", value="no_detection"),
    SignalThreshold(verdict="Low", value="suspect"),
    SignalThreshold(verdict="Medium", value="compromised"),
    SignalThreshold(verdict="High", value="compromised"),
)
# The scenario: isolate without review only when the EDR reports the host compromised,
# never a domain controller, and only for an open incident.
SIGNAL_RULES = Ruleset(
    rules=(
        Rule(
            id="isolate-open-incident",
            action="endpoint.isolate",
            effect="ALLOW",
            when=(Condition(kind="fact", name="incident_status", operator="is", values=("OPEN",)),),
        ),
        Rule(
            id="isolate-never-domain-controller",
            action="endpoint.isolate",
            effect="DENY",
            when=(
                Condition(kind="fact", name="role", operator="is", values=("domain_controller",)),
            ),
        ),
        Rule(
            id="isolate-review-unless-compromised",
            action="endpoint.isolate",
            effect="REVIEW",
            when=(
                Condition(
                    kind="fact", name="compromise", operator="is_not", values=("compromised",)
                ),
            ),
        ),
    )
)


def signal_bundle(
    tenant: UUID,
    account: UUID,
    sources: tuple[UUID, ...],
    *,
    thresholds: tuple[SignalThreshold, ...] = MDE_THRESHOLDS,
    rules: Ruleset = SIGNAL_RULES,
    signal_mappings: tuple[SignalMapping, ...] | None = None,
) -> BundleContent:
    reference = MappingRef(
        operation_ref="endpoint.isolate",
        account_id=account,
        mapping_version="map-v1",
        schema_version="action.v1",
        context_contract_version=V2,
    )
    entries = signal_mappings
    if entries is None:
        entries = (
            SignalMapping(
                context_contract_version=V2,
                capability=CAPABILITY,
                admitted_sources=sources,
                thresholds=thresholds,
            ),
        )
    return ruleset_bundle(
        rules,
        tenant_id=tenant,
        bundle_id=uuid4(),
        mappings=(reference,),
        signal_mappings=entries or None,
    )


def register(
    admin_engine: Any, world: dict[str, Any], output: Any, **changes: Any
) -> tuple[UUID, str]:
    values: dict[str, Any] = {
        "label": "MDE lab",
        "producer": PRODUCER,
        "version_min": "0.1.0",
        "version_max": "0.9.9",
        "capabilities": (CAPABILITY,),
        "principals": (world["identity"].principal_id,),
        "lifetime": timedelta(hours=8),
        "output": output,
        # Registered at the world's clock, which every admission in these tests uses as its
        # time: a source created after it would refuse them as not yet valid.
        "now": world["clock"].now(),
    }
    values.update(changes)
    grant = create_signal_source(
        admin_engine, world["identity"].tenant_id, world["admin"].principal_id, **values
    )
    return grant.source_id, grant.output.read_text(encoding="ascii").strip()


def move_to_v2(admin_engine: Any, tenant: UUID) -> None:
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        conn.execute(
            text(
                "UPDATE execbound.operation_mappings SET context_contract_version = :v "
                "WHERE tenant_id = :t AND operation_ref = 'endpoint.isolate'"
            ),
            {"v": V2, "t": tenant},
        )


@pytest.fixture
def signal_world(world, db, admin_engine, tmp_path):
    """`world` with its isolation mapping on v2, one registered source and the scenario live."""
    tenant = world["identity"].tenant_id
    move_to_v2(admin_engine, tenant)
    source, token = register(admin_engine, world, tmp_path / "signal-token")
    bundle = signal_bundle(tenant, world["account"], (source,))
    create_bundle(db, world["admin"], bundle, world["clock"])
    validate_bundle(db, world["admin"], bundle.bundle_id, world["clock"])
    activate_bundle(db, world["admin"], bundle.bundle_id, world["clock"])
    return {**world, "source": source, "token": token, "signal_bundle": bundle}


def post_signal(
    db: Database, world: dict[str, Any], verdict: str, **changes: Any
) -> dict[str, Any]:
    """Admit one record about the world's target, observed at the world's clock by default."""
    now = world["clock"].now()
    fields = signal_fields(
        world["account"],
        now,
        verdict=verdict,
        event_id=changes.pop("event_id", f"device-01:{uuid4().hex[:12]}"),
        **changes,
    )
    return admit_raw(
        db, world["identity"].tenant_id, world["source"], world["token"], now, **fields
    )
