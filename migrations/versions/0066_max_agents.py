"""An agent limit is a number the workspace carries, not a plan (#257, #496 unit A3).

`tenants.max_agents` is null, which means uncapped, or a limit of zero or more. It replaces the
`CASE t.plan WHEN 'free' THEN 3 ELSE NULL END` that `0044_hosted_free` wrote into
`admin_create_principal` and `admin_reactivate_principal`: both now read `t.max_agents` under
the same `FOR NO KEY UPDATE` on the tenant row, against the same count of live and sleeping
agents, raising the same `PLAN_LIMIT`, and nothing else in either changes. The backfill gives
every `free` tenant 3 and leaves every other tenant null, the limit each one had under 0044's
`CASE`, so no decision changes at this revision. A workspace stays uncapped unless its operator
sets the column or a plugin sets it from its own plans.

The three dormant definer functions that put a tenant on `free` (`community_provision`,
`onboarding_claim` and `sandbox_fallback`) set `max_agents = 3` in the same statement, so a
workspace they make is capped the moment it exists. Being dormant (`0065_dormant_grants`), none
of them can be called by a runtime whose plugins do not claim them. `agents_sleep` still reads
`plan`: dormancy is the plugin's rule about its plans.

Every function is patched in place, as `0057_api_key_never` and `0061_replaced_principals`
patch theirs: the live definition is read, each fragment must occur in it exactly once, and
`CREATE OR REPLACE` keeps the owner, `SECURITY DEFINER` and the grants. Restating 0044's text
would undo 0047's fence and role-aware actor check and 0061's `PRINCIPAL_REPLACED`.

Both directions take the tenants table's lock first, so an apply beside live traffic waits
for it rather than deadlocking with it, and lift its `FORCE` only around the statements that
must see every tenant, so an owner that does not bypass row security sees them all. The
downgrade refuses while any tenant's limit differs from what its plan gave under 0044, because
dropping the column would lose a limit set by hand.
"""

from alembic import op
from sqlalchemy import text

revision = "0066_max_agents"
down_revision = "0065_dormant_grants"
branch_labels = None
depends_on = None

PLAN_CAP = "SELECT CASE t.plan WHEN 'free' THEN 3 ELSE NULL END INTO v_limit"
MAX_AGENTS = "SELECT t.max_agents INTO v_limit"
PROVISION = """\
        INSERT INTO execbound.tenants(tenant_id, name, active, plan, slug, provisioned_at)
        VALUES (p_tenant, p_name, true, 'free', p_slug, p_now);
"""
PROVISION_CAPPED = """\
        INSERT INTO execbound.tenants(tenant_id, name, active, plan, max_agents, slug,
                                      provisioned_at)
        VALUES (p_tenant, p_name, true, 'free', 3, p_slug, p_now);
"""
CLAIM = "UPDATE execbound.tenants SET name = v_name, active = true, plan = 'free'\n"
CLAIM_CAPPED = (
    "UPDATE execbound.tenants SET name = v_name, active = true, plan = 'free', max_agents = 3\n"
)
FALLBACK = "UPDATE execbound.tenants SET plan = 'free' WHERE tenant_id = v_tenant;"
FALLBACK_CAPPED = (
    "UPDATE execbound.tenants SET plan = 'free', max_agents = 3 WHERE tenant_id = v_tenant;"
)
# (function, fragment as `0065_dormant_grants` leaves it, fragment as this revision leaves it),
# applied in order on upgrade and undone in reverse on downgrade.
PATCHES = (
    ("admin_create_principal", PLAN_CAP, MAX_AGENTS),
    ("admin_reactivate_principal", PLAN_CAP, MAX_AGENTS),
    ("community_provision", PROVISION, PROVISION_CAPPED),
    ("onboarding_claim", CLAIM, CLAIM_CAPPED),
    ("sandbox_fallback", FALLBACK, FALLBACK_CAPPED),
)


def _replace(function: str, before: str, after: str) -> None:
    conn = op.get_bind()
    definition = conn.execute(
        text(
            "SELECT pg_get_functiondef(p.oid) FROM pg_proc p "
            "JOIN pg_namespace n ON n.oid = p.pronamespace "
            "WHERE n.nspname = 'execbound' AND p.proname = :name"
        ),
        {"name": function},
    ).scalar_one()
    # A definition that no longer carries the fragment exactly once was changed by something
    # this migration does not know, and is refused rather than guessed at.
    if definition.count(before) != 1:
        raise RuntimeError(f"{function} no longer has the fragment {revision} patches")
    # CREATE OR REPLACE keeps the owner, SECURITY DEFINER and the grants, none on a dormant
    # function. Straight to the driver, every percent sign doubled: psycopg reads `%` as a
    # placeholder, and three of these declare `%ROWTYPE` variables.
    conn.exec_driver_sql(definition.replace(before, after).replace("%", "%%"))


def _all_tenants(statement: str) -> None:
    op.execute("ALTER TABLE execbound.tenants NO FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security = off")
    op.execute(statement)
    op.execute("ALTER TABLE execbound.tenants FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security = on")


def upgrade() -> None:
    op.execute("LOCK TABLE execbound.tenants IN ACCESS EXCLUSIVE MODE")
    op.execute(
        "ALTER TABLE execbound.tenants ADD COLUMN max_agents integer "
        "CONSTRAINT tenants_max_agents CHECK (max_agents IS NULL OR max_agents >= 0)"
    )
    _all_tenants("UPDATE execbound.tenants SET max_agents = 3 WHERE plan = 'free'")
    for function, before, after in PATCHES:
        _replace(function, before, after)


def downgrade() -> None:
    op.execute("LOCK TABLE execbound.tenants IN ACCESS EXCLUSIVE MODE")
    op.execute("ALTER TABLE execbound.tenants NO FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security = off")
    differs = (
        op.get_bind()
        .execute(
            text(
                "SELECT EXISTS (SELECT 1 FROM execbound.tenants WHERE max_agents "
                "IS DISTINCT FROM CASE plan WHEN 'free' THEN 3 END)"
            )
        )
        .scalar_one()
    )
    op.execute("ALTER TABLE execbound.tenants FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security = on")
    if differs:
        raise RuntimeError("An agent limit differs from its plan's; downgrade refused")
    for function, before, after in reversed(PATCHES):
        _replace(function, after, before)
    op.execute("ALTER TABLE execbound.tenants DROP COLUMN max_agents")
