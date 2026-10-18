# SPDX-License-Identifier: AGPL-3.0-only
"""Session revocation and rule writes share the real tenant transaction fence."""

from concurrent.futures import ThreadPoolExecutor
from threading import Event
from uuid import UUID

import pytest
from console_api_fixtures import console_client
from sqlalchemy import event as sa_event
from sqlalchemy import text
from test_approval_group_rules import rule, setup_group
from test_execution import registry as registry
from test_execution import world as world
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

from execbound import approval_rules
from execbound.execution import store
from execbound.surfaces.sessions import SessionError, issue_session, load_session


def test_rule_write_rechecks_a_session_revoked_while_waiting_for_the_fence(
    db, runtime, admin_engine, world
):
    tenant = world["admin"].tenant_id
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        group = setup_group(client, world)
        response = rule(client, world, group)
        assert response.status_code == 200, response.text
        rule_id = UUID(response.json()["rule_id"])
    issued = issue_session(db, world["admin"], clock=world["clock"])
    session = load_session(db, issued.token, clock=world["clock"])
    waiting = Event()

    def reached_fence(conn, cursor, statement, parameters, context, executemany):
        # The old implementation first waited inside the definer call, after checking
        # the session. The corrected guard enters the fence before checking it.
        if "tenant_policy_control" in statement or "approval_rule_change(" in statement:
            waiting.set()

    with ThreadPoolExecutor(max_workers=1) as pool:
        with db.transaction(tenant) as blocker:
            store.fence(blocker, tenant, world["clock"])
            sa_event.listen(db.engine, "before_cursor_execute", reached_fence)
            try:
                future = pool.submit(
                    approval_rules.change_rule,
                    runtime,
                    session,
                    rule_id,
                    {"operation": "disable"},
                    "Retire the rule",
                )
                assert waiting.wait(timeout=10), "the rule write did not reach its fence"
                blocker.execute(
                    text(
                        "UPDATE execbound.human_sessions SET revoked_at=:n "
                        "WHERE tenant_id=:t AND session_id=:s"
                    ),
                    {"n": world["clock"].now(), "t": tenant, "s": session.session_id},
                )
            finally:
                sa_event.remove(db.engine, "before_cursor_execute", reached_fence)
        with pytest.raises(SessionError):
            future.result(timeout=20)
    with db.transaction(tenant) as conn:
        assert (
            conn.execute(
                text(
                    "SELECT active FROM execbound.approval_rules WHERE tenant_id=:t AND rule_id=:r"
                ),
                {"t": tenant, "r": rule_id},
            ).scalar_one()
            is True
        )
