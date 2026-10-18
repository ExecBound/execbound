# SPDX-License-Identifier: AGPL-3.0-only
"""Human group review rules; current membership is never copied into durable grants."""

import json
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import DBAPIError

from execbound import access_control
from execbound.audit import append_event
from execbound.execution import store
from execbound.operations import PRODUCTION_ACTIONS
from execbound.runtime import Runtime
from execbound.secrets import secret_shaped
from execbound.surfaces.sessions import Session, check_session


class ApprovalRuleError(ValueError):
    def __init__(self, code: str, *, field: str | None = None):
        self.code = code
        # `change_rule` answers the reason, the name and the choice counts alike with
        # `INVALID_BODY` (the domain's own code, never widened), so the field names which
        # one was at fault; every other raise leaves it unset.
        self.field = field
        super().__init__(code)


def validate_choices(actions: list[str], targets: list[UUID]) -> None:
    if (
        not 1 <= len(actions) <= 20
        or not 1 <= len(targets) <= 100
        or len(set(actions)) != len(actions)
        or len(set(targets)) != len(targets)
    ):
        raise ApprovalRuleError("INVALID_BODY")
    if any(action not in PRODUCTION_ACTIONS.names for action in actions):
        raise ApprovalRuleError("INVALID_ACTION")


def _guard(conn: Connection, runtime: Runtime, session: Session) -> None:
    store.fence(conn, session.identity.tenant_id, runtime.clock)
    store.identity_check(conn, session.identity, runtime.clock, "ADMIN")
    check_session(conn, session, runtime.clock)
    if not access_control.has_permission(
        conn, session.identity.tenant_id, session.identity.principal_id, "access.manage"
    ):
        raise ApprovalRuleError("INVALID_ACTOR")


def read_rules(runtime: Runtime, session: Session) -> dict[str, Any]:
    identity = session.identity
    with runtime.db.transaction(identity.tenant_id) as conn:
        _guard(conn, runtime, session)
        rules = [
            dict(row)
            for row in conn.execute(
                text("""
            SELECT r.rule_id,r.name,r.space_id,s.name AS space_name,r.group_id,
                   g.name AS group_name,r.active,
                   ARRAY(SELECT action FROM execbound.approval_rule_actions a
                       WHERE a.tenant_id=r.tenant_id AND a.rule_id=r.rule_id
                       ORDER BY action) AS actions,
                   ARRAY(SELECT canonical_target_id FROM execbound.approval_rule_targets t
                       WHERE t.tenant_id=r.tenant_id AND t.rule_id=r.rule_id
                       ORDER BY canonical_target_id) AS targets,
                   (SELECT count(*) FROM execbound.access_group_members m
                    WHERE m.tenant_id=r.tenant_id AND m.group_id=r.group_id
                    AND execbound.access_has_permission(
                        m.principal_id,'approvals.decide',r.space_id,false)) AS eligible_reviewers
            FROM execbound.approval_rules r
            JOIN execbound.access_groups g USING(tenant_id,group_id)
            JOIN execbound.spaces s USING(tenant_id,space_id)
            WHERE r.tenant_id=:t ORDER BY r.active DESC,r.name,r.rule_id LIMIT 500
        """),
                {"t": identity.tenant_id},
            ).mappings()
        ]
        return {
            "rules": rules,
            "actions": [
                {"id": name, "name": PRODUCTION_ACTIONS.action(name).label}
                for name in sorted(PRODUCTION_ACTIONS.names)
            ],
        }


def change_rule(
    runtime: Runtime, session: Session, rule_id: UUID | None, body: dict[str, Any], reason: str
) -> UUID:
    if not 1 <= len(reason.strip()) <= 500:
        raise ApprovalRuleError("INVALID_BODY", field="reason")
    if secret_shaped(reason):
        raise ApprovalRuleError("INVALID_BODY", field="reason")
    if secret_shaped(body.get("name")):
        raise ApprovalRuleError("INVALID_BODY", field="name")
    if body.get("operation") == "save":
        validate_choices(body["actions"], [UUID(value) for value in body["targets"]])
    identity = session.identity
    with runtime.db.transaction(identity.tenant_id) as conn:
        _guard(conn, runtime, session)
        try:
            changed = conn.execute(
                text("SELECT execbound.approval_rule_change(:actor,:rule,CAST(:body AS jsonb))"),
                {"actor": identity.principal_id, "rule": rule_id, "body": json.dumps(body)},
            ).scalar_one()
        except DBAPIError as exc:
            message = getattr(getattr(exc.orig, "diag", None), "message_primary", None)
            allowed = {
                "INVALID_BODY",
                "INVALID_ACTOR",
                "INVALID_TENANT",
                "INVALID_ACTION",
                "INVALID_TARGET",
                "INVALID_SPACE",
                "NOT_FOUND",
                "LIMIT_REACHED",
            }
            raise ApprovalRuleError(message if message in allowed else "UNAVAILABLE") from None
        append_event(
            conn,
            identity.tenant_id,
            identity.principal_id,
            "approval_rule.changed",
            {"rule_id": str(changed), "change": body, "reason": reason.strip()},
        )
        return UUID(str(changed))
