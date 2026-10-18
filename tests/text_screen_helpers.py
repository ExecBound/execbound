# SPDX-License-Identifier: AGPL-3.0-only
"""Shared assertions for the text-screen tests (T7.7): reading an owner connection's audit
chain for a finding or a kind's count, and checking that a refusal names its code and never
the value it refused.

Every statement here names ``tenant_id = :t`` itself, rather than leaning on a fence set on
the connection, because ``admin_engine`` connects as the owner, who bypasses row security:
a fence set on one of its connections limits nothing, so the predicate is the only thing
that actually scopes a read through it to one tenant.
"""

import pytest
from secret_shapes import FREE_TEXT, FREE_TEXT_IDS
from sqlalchemy import text

from execbound.secrets import find_secrets

# A success kind more than one boundary's tests read, shared here so neither file's copy can
# drift from the other's.
APPROVAL_RULE_KIND = "approval_rule.changed"


def over_free_text(argname):
    """`@pytest.mark.parametrize(argname, FREE_TEXT, ids=FREE_TEXT_IDS)`: every text-screen
    test parametrized over `FREE_TEXT` uses this instead of spelling out the mark itself, so
    its node id, and so a JUnit report and a CI log, names the shape (``stripe``, ``jwt``, ...)
    and never carries the credential-shaped sample."""
    return pytest.mark.parametrize(argname, FREE_TEXT, ids=FREE_TEXT_IDS)


def _payloads(engine, tenant):
    with engine.begin() as conn:
        return (
            conn.execute(
                text("SELECT payload FROM execbound.audit_events WHERE tenant_id = :t"),
                {"t": tenant},
            )
            .scalars()
            .all()
        )


def assert_nothing_found(engine, tenant):
    """No payload in this tenant's audit chain holds anything ``find_secrets`` flags."""
    assert not any(find_secrets(payload, limit=1) for payload in _payloads(engine, tenant))


def kind_count(engine, tenant, kind):
    with engine.begin() as conn:
        return conn.execute(
            text("SELECT count(*) FROM execbound.audit_events WHERE tenant_id = :t AND kind = :k"),
            {"t": tenant, "k": kind},
        ).scalar_one()


# Every table `row_count` may read. Fixed, so a table name never reaches the query from a
# caller's own input: `row_count` refuses anything outside this set rather than interpolate it.
_ROW_COUNT_TABLES = frozenset(
    {
        "principals",
        "principal_groups",
        "access_groups",
        "spaces",
        "personal_access_tokens",
        "signal_sources",
        "context_sources",
        "executor_keys",
        "resources",
        "resource_facts",
        "operation_mappings",
        "workspace_invitations",
        "policy_bundle_contents",
        "policy_bundle_lifecycle",
    }
)


def row_count(engine, tenant, table):
    """How many of this tenant's rows ``table`` holds, for a boundary whose refusal must
    leave the row count exactly where it was. ``table`` must name one of `_ROW_COUNT_TABLES`."""
    if table not in _ROW_COUNT_TABLES:
        raise ValueError(f"row_count: {table!r} is not one of {sorted(_ROW_COUNT_TABLES)}")
    # `table` is checked against the fixed set above, never built from a caller's value, so
    # this interpolation never carries anything this module did not name itself.
    with engine.begin() as conn:
        return conn.execute(
            text(f"SELECT count(*) FROM execbound.{table} WHERE tenant_id = :t"),
            {"t": tenant},
        ).scalar_one()


def assert_refused_unquoted(raised, code, value):
    """The refusal carries its code and never the value it refused."""
    assert raised.value.code == code
    assert value not in str(raised.value) and value not in repr(raised.value)
