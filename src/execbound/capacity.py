# SPDX-License-Identifier: AGPL-3.0-only
"""A workspace's agent limit and how much of it the workspace holds (#257, #496).

`tenants.max_agents` is the only cap: null means uncapped, which every workspace is unless its
operator sets a limit or a plugin sets one from its own plans. What it counts is exactly what
`admin_create_principal` and `admin_reactivate_principal` count, live and sleeping agent
principals and never one a person deactivated by hand, so a page that shows the number and the
refusal that enforces it cannot disagree. Administrative only: nothing that decides or
dispatches a request reads it (T5.20).
"""

from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Connection

_CAPACITY = """
SELECT t.max_agents,
       count(p.principal_id) FILTER (WHERE p.active OR p.dormant_at IS NOT NULL) AS held,
       count(p.principal_id) FILTER (WHERE p.dormant_at IS NOT NULL) AS dormant
  FROM execbound.tenants t
  LEFT JOIN execbound.principals p ON p.tenant_id = t.tenant_id AND p.kind = 'AGENT'
 WHERE t.tenant_id = :tenant
 GROUP BY t.tenant_id, t.max_agents
"""


@dataclass(frozen=True)
class AgentCapacity:
    agent_limit: int | None
    agents_held: int
    agents_dormant: int


def agent_capacity(conn: Connection, tenant: UUID) -> AgentCapacity:
    """The tenant's limit and its held and sleeping agents, over a connection fenced to it."""
    row = conn.execute(text(_CAPACITY), {"tenant": tenant}).mappings().one()
    limit = row["max_agents"]
    return AgentCapacity(
        agent_limit=None if limit is None else int(limit),
        agents_held=int(row["held"]),
        agents_dormant=int(row["dormant"]),
    )
