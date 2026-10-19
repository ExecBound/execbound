# SPDX-License-Identifier: AGPL-3.0-only
"""Agent bindings: the one write path for which governed principal a discovered agent is.

Both callers, the Agents page and Monitoring's ``link-agent`` command, bind and unbind here,
inside their own transaction, so the definer function and its audit event commit together
or not at all. The functions keep ``monitor_agents.linked_principal_id`` in step with the
active binding; nothing else can move that column (migration 0037).
"""

from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import DBAPIError

from execbound.administration import AdministrationError
from execbound.audit import acted_with, append_event
from execbound.identity import Identity
from execbound.secrets import secret_shaped

# The codes the two functions raise; anything else is reported as unavailable.
CODES = frozenset(
    {
        "INVALID_TENANT",
        "INVALID_ACTOR",
        "INVALID_PRINCIPAL",
        "INVALID_AGENT",
        "INVALID_STATE",
        "INVALID_REASON",
        # The synthetic directory's actor exists nowhere, so it is never bound (0099's trigger).
        "SYNTHETIC_ACTOR",
    }
)


def _call(conn: Connection, statement: str, params: dict[str, Any]) -> Any:
    try:
        return conn.execute(text(statement), params).scalar_one()
    except DBAPIError as exc:
        diagnostic = getattr(exc.orig, "diag", None)
        message = getattr(diagnostic, "message_primary", None)
        code = message if message in CODES else "ADMINISTRATION_UNAVAILABLE"
        raise AdministrationError(code) from None


def active_binding(conn: Connection, tenant: UUID, *, agent: UUID) -> Any:
    """The agent's active binding row, or None."""
    return (
        conn.execute(
            text(
                "SELECT binding_id, agent_id, principal_id, bound_by, bound_at "
                "FROM execbound.agent_bindings "
                "WHERE tenant_id = :t AND agent_id = :a AND unbound_at IS NULL"
            ),
            {"t": tenant, "a": agent},
        )
        .mappings()
        .one_or_none()
    )


def bind(conn: Connection, identity: Identity, agent: UUID, principal: UUID) -> UUID:
    """Bind ``agent`` to ``principal`` and audit it, in the caller's transaction."""
    binding = _call(
        conn,
        "SELECT execbound.admin_bind_agent(:actor, :agent, :principal)",
        {"actor": identity.principal_id, "agent": agent, "principal": principal},
    )
    append_event(
        conn,
        identity.tenant_id,
        identity.principal_id,
        "agent.bound",
        {
            "binding_id": str(binding),
            "agent_id": str(agent),
            "principal_id": str(principal),
            **acted_with(identity.credential_id),
        },
    )
    return UUID(str(binding))


def unbind(conn: Connection, identity: Identity, binding: UUID, reason: str) -> dict[str, str]:
    """Withdraw an active binding with its reason and audit it, in the caller's transaction."""
    if secret_shaped(reason):
        raise AdministrationError("INVALID_REASON")
    released = _call(
        conn,
        "SELECT execbound.admin_unbind_agent(:actor, :binding, :reason)",
        {"actor": identity.principal_id, "binding": binding, "reason": reason},
    )
    ids = {"agent_id": str(released["agent_id"]), "principal_id": str(released["principal_id"])}
    append_event(
        conn,
        identity.tenant_id,
        identity.principal_id,
        "agent.unbound",
        {
            "binding_id": str(binding),
            **ids,
            "reason": reason.strip(),
            **acted_with(identity.credential_id),
        },
    )
    return ids
