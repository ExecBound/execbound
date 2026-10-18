"""Delete unused groups under the same serialized access-management boundary."""

import importlib.util
from pathlib import Path

from alembic import op

revision = "0049_unused_groups"
down_revision = "0048_approval_rules"
branch_labels = None
depends_on = None

DELETE = """
    ELSIF p_operation='delete_group' THEN
        IF NOT EXISTS(SELECT 1 FROM execbound.access_groups
            WHERE tenant_id=v_tenant AND group_id=v_id) THEN RAISE EXCEPTION 'NOT_FOUND'; END IF;
        IF EXISTS(SELECT 1 FROM execbound.access_group_members
            WHERE tenant_id=v_tenant AND group_id=v_id)
            OR EXISTS(SELECT 1 FROM execbound.access_role_grants
                WHERE tenant_id=v_tenant AND group_id=v_id)
            OR EXISTS(SELECT 1 FROM execbound.approval_rules
                WHERE tenant_id=v_tenant AND group_id=v_id AND active)
            THEN RAISE EXCEPTION 'GROUP_IN_USE'; END IF;
        DELETE FROM execbound.approval_rule_actions a USING execbound.approval_rules r
            WHERE a.tenant_id=v_tenant AND r.tenant_id=a.tenant_id
              AND r.rule_id=a.rule_id AND r.group_id=v_id;
        DELETE FROM execbound.approval_rule_targets a USING execbound.approval_rules r
            WHERE a.tenant_id=v_tenant AND r.tenant_id=a.tenant_id
              AND r.rule_id=a.rule_id AND r.group_id=v_id;
        DELETE FROM execbound.approval_rules WHERE tenant_id=v_tenant AND group_id=v_id;
        DELETE FROM execbound.access_groups WHERE tenant_id=v_tenant AND group_id=v_id;
"""


def previous() -> str:
    spec = importlib.util.spec_from_file_location(
        "access_revision", Path(__file__).with_name("0047_access_control.py")
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return str(module.CHANGE).replace("CREATE FUNCTION", "CREATE OR REPLACE FUNCTION", 1)


def upgrade() -> None:
    # Existing tenant lock, authority recheck, last-admin guard and function ACLs are kept.
    original = previous()
    marker = "    ELSIF p_operation='set_members' THEN"
    assert original.count(marker) == 1
    op.execute(original.replace(marker, DELETE + marker))


def downgrade() -> None:
    op.execute(previous())
