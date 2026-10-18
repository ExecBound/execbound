# SPDX-License-Identifier: AGPL-3.0-only
"""What an external agent can reach, per action and per path.

One row per ``(action, path_kind, path_ref)``, never one per action. An agent that holds a
directory grant reaching ``identity.disable`` *and* sends requests through ExecBound has two
answers to "through which path", and collapsing them would hide exactly the alternate route
this unit exists to show.

A certainty is only ever what its own path can establish: a grant proves capability, not that
anything ran; an observation proves something ran, not that anything stood in front of it; an
execution through the kernel proves both, for that route only. Freshness is read, not written:
a row whose ``valid_until`` has passed reads as ``unknown`` rather than going on asserting a
grant nobody has looked at since.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Connection

from execbound.monitoring.grant_catalog import ENTRA, PRODUCTION_GRANTS, GrantCatalog

# A grant read is a statement about the directory at collection time, and weekly collection
# is the slowest cadence this design supports.
INFERRED_VALIDITY = timedelta(days=7)
# An execution or an observation is a historical fact; its currency as evidence of reach
# decays, but far more slowly than a permission snapshot does.
EVIDENCE_VALIDITY = timedelta(days=30)

PATH_KINDS = {
    "graph_role": "grant",
    "graph_scope": "grant",
    "directory_role": "role",
    "tines_credential": "grant",
    "inherited_roles": "inherited",
    "inherited_scopes": "inherited",
}

GOVERNED_ACTIONS = text("""
    SELECT om.action,
           COALESCE((m->>'external_executor')::boolean, false) AS external_executor,
           COALESCE((m->>'observe_only')::boolean, false) AS observe_only
    FROM execbound.space_policy_selection t
    JOIN execbound.policy_bundle_contents b
      ON b.tenant_id = t.tenant_id AND b.bundle_id = t.bundle_id
    JOIN execbound.policy_bundle_lifecycle s
      ON s.tenant_id = b.tenant_id AND s.bundle_id = b.bundle_id
         AND s.content_hash = b.content_hash
    CROSS JOIN LATERAL jsonb_array_elements(b.content->'mappings') AS m
    JOIN execbound.operation_mappings om
      ON om.tenant_id = t.tenant_id AND om.operation_ref = m->>'operation_ref' AND om.active
    JOIN execbound.connector_accounts ca
      ON ca.tenant_id = om.tenant_id AND ca.account_id = om.account_id
         AND ca.provider = om.provider AND ca.active
    WHERE t.tenant_id = :tenant AND s.state = 'ACTIVE'
""")


@dataclass(frozen=True, slots=True)
class ReachRow:
    action: str
    path_kind: str
    path_ref: str
    certainty: str
    enforcement_mode: str
    catalog_version: str
    validity: timedelta = INFERRED_VALIDITY


def from_grants(
    grants: Any, *, catalog: GrantCatalog = PRODUCTION_GRANTS
) -> tuple[tuple[ReachRow, ...], int]:
    """Inferred reach, and the number of grants whose reach this catalog cannot establish.

    An unresolved grant produces no row, because a row has to name an action and naming one
    we cannot establish would be the invention the catalog exists to prevent. It is counted
    instead, and shown beside the rows: "this agent holds three permissions we cannot explain"
    is a finding, where a silent zero would be a false clean bill.
    """
    rows: dict[tuple[str, str, str], ReachRow] = {}
    unresolved = 0
    for grant in grants:
        entries = catalog.lookup(ENTRA, grant.grant_kind, grant.resource_ref, grant.value)
        if not entries:
            unresolved += 1
            continue
        path_kind = PATH_KINDS.get(grant.grant_kind, "grant")
        for entry in entries:
            key = (entry.action, path_kind, grant.path_ref)
            rows[key] = ReachRow(
                action=entry.action,
                path_kind=path_kind,
                path_ref=grant.path_ref,
                certainty="inferred",
                # Nothing ExecBound operates stands between an agent and its own grant.
                enforcement_mode="unknown",
                catalog_version=catalog.version,
            )
    return tuple(rows.values()), unresolved


def governed(conn: Connection, tenant: UUID) -> dict[str, str]:
    """Actions the tenant's active bundle governs, and the mode each governed path supports.

    An observe-only mapping governs nothing: it watches and returns, so it yields no path at
    all rather than a path claiming enforcement. A mapping that hands the act to the
    customer's own executor is ``integrated``, not ``native``, because the credential stays
    with that executor and the claim is bounded by the integration that was tested.
    """
    modes = {}
    for row in conn.execute(GOVERNED_ACTIONS, {"tenant": tenant}).mappings():
        if row["observe_only"]:
            continue
        modes[row["action"]] = "integrated" if row["external_executor"] else "native"
    return modes


def execbound_paths(modes: dict[str, str], principal_id: UUID | None) -> tuple[ReachRow, ...]:
    """The governed path an agent has, which exists only once it is linked to a principal.

    A tenant mapping governs the tenant's own route. Until an ADMIN says which ExecBound
    principal *is* this external agent, nothing connects the two, and claiming the agent's
    path is governed would be a guess about identity.
    """
    if principal_id is None:
        return ()
    return tuple(
        ReachRow(
            action=action,
            path_kind="execbound",
            path_ref=str(principal_id),
            certainty="inferred",
            enforcement_mode=mode,
            catalog_version=PRODUCTION_GRANTS.version,
        )
        for action, mode in sorted(modes.items())
    )


def effective(row: Any, now: datetime) -> str:
    """The certainty a row still supports. Expired proof is unknown, not what it once was."""
    return "unknown" if row["valid_until"] <= now else str(row["certainty"])
