# SPDX-License-Identifier: AGPL-3.0-only
"""Owner-provisioned groups, scoped rules and readers for the limit scope scenarios."""

import os
from uuid import uuid4

import pytest
from sqlalchemy import text
from test_execution import activate, provision_identity

from execbound import administration
from execbound.execution import store
from execbound.policy.models import LimitRule


@pytest.fixture
def owner(seeded):
    """The owner role's engine; group provisioning is audited through it, never the runtime."""
    engine = administration.owner_engine(os.environ["TEST_MIGRATION_DATABASE_URL"])
    yield engine
    engine.dispose()


def group(engine, world, *members, name=None):
    """A group of the world's tenant holding ``members`` (AGENT identities), owner-provisioned."""
    tenant = world["identity"].tenant_id
    actor = world["admin"].principal_id
    created = administration.create_group(engine, tenant, name or f"group-{uuid4().hex[:8]}", actor)
    for member in members:
        administration.assign_group(engine, tenant, created, member.principal_id, actor)
    return created


def rule(**changes):
    """A total ceiling of three on isolation that escalates, qualified by ``changes``."""
    return LimitRule(
        **{
            "rule_id": "scoped",
            "action": "endpoint.isolate",
            "scope": "principal",
            "window_seconds": 3600,
            "max_targets": 3,
            "budget": "total",
            "on_exceed": "REQUIRE_APPROVAL",
            **changes,
        }
    )


def scoped_bundle(db, world, *rules, base=None):
    """Activate a copy of the world's bundle (or ``base``) whose limits are exactly ``rules``."""
    if base is not None:
        world["bundle"] = base
    return activate(db, world, limits=tuple(rules))


def agent(admin_engine, db, world):
    """A fresh AGENT of the world's tenant with its own credential."""
    return provision_identity(
        admin_engine, db, world["identity"].tenant_id, "AGENT", world["clock"].now()
    )


def usage(db, world, identity, execution_id, *, observed=False):
    """The kernel's own projection for ``identity`` over the retained rows of the active bundle.

    The frozen plan is read the way admission reads it, so the snapshot carries that
    execution's account; the counts are the store's, in each rule's scope.
    """
    tenant = world["identity"].tenant_id
    with db.transaction(tenant) as conn:
        plan = store.frozen(store.read(conn, tenant, execution_id))
        return store.usage(
            conn, identity, world["bundle"], world["clock"], frozen=plan, observed=observed
        )


def counted(snapshot):
    return {c.rule_id: (c.confirmed_targets, c.unresolved_targets) for c in snapshot.counts}


def transition_payload(engine, tenant, execution_id, state):
    """The payload of the one transition of ``execution_id`` into ``state``, as retained."""
    with engine.connect() as conn:
        return conn.execute(
            text(
                "SELECT payload FROM execbound.execution_events "
                "WHERE tenant_id=:t AND execution_id=:e AND to_state=:s"
            ),
            {"t": tenant, "e": execution_id, "s": state},
        ).scalar_one()


def audit_payloads(engine, tenant, kind):
    with engine.connect() as conn:
        return (
            conn.execute(
                text(
                    "SELECT payload FROM execbound.audit_events "
                    "WHERE tenant_id=:t AND kind=:k ORDER BY sequence"
                ),
                {"t": tenant, "k": kind},
            )
            .scalars()
            .all()
        )


def impact_groups(engine, tenant):
    """Every retained impact row's group list, by execution."""
    with engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT execution_id, group_ids FROM execbound.execution_impact WHERE tenant_id=:t"
            ),
            {"t": tenant},
        ).all()
    return {row.execution_id: row.group_ids for row in rows}
