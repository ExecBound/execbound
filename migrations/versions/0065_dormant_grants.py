"""The tables and functions only a plugin uses hold no grant but the owner's (#496, unit A3).

Every migration ships in the one shared chain, so these objects exist on every install: seven
tables and the `SECURITY DEFINER` functions below, among them `community_provision`, which
creates a workspace with its first administrator. Until this revision the runtime role could
read those tables and call those functions on every database. This revision takes all of it
away, from the runtime role, from PUBLIC and from the three roles Supabase adds, following the
revoke convention of `0063_personal_access_tokens`. `execbound.db.DORMANT_TABLES` and
`DORMANT_FUNCTIONS` name the same objects, `check_runtime` refuses a database where one of them
holds a grant no loaded plugin claims, and the plugin that claims them grants them back, on its
own database, in the transaction that applies this revision.

The objects are named here rather than read from `execbound.db`: a migration never imports
application code, so this revision revokes exactly these, whatever the catalog later adds. An
object of this kind added after it is created without a grant and never needs revoking.

`onboarding_invitation_revoke` (0042) never had PUBLIC's default EXECUTE taken off it. This
revision takes that too, and the downgrade gives back only what the runtime role held.
"""

from alembic import op
from sqlalchemy import text

revision = "0065_dormant_grants"
down_revision = "0064_scheduled_jobs"
branch_labels = None
depends_on = None

TABLES = (
    "community_allocations",
    "product_counts",
    "onboarding_slots",
    "onboarding_invitations",
    "signup_requests",
    "signup_messages",
    "account_preferences",
)
FUNCTIONS = (
    "product_count(text, text)",
    "onboarding_claim(uuid, text, text, uuid, uuid, text, timestamptz, timestamptz)",
    "sandbox_reattest(uuid)",
    "onboarding_invite(text, text, timestamptz)",
    "onboarding_invitation_rekey(uuid, text)",
    "onboarding_invitation_revoke(uuid)",
    "sandbox_expire(text, timestamptz)",
    "sandbox_notice(timestamptz)",
    "sandbox_fallback(timestamptz)",
    "agents_sleep(timestamptz)",
    "signup_request(uuid, text, text, boolean, text, timestamptz, text, integer, integer, "
    "integer, integer, integer)",
    "signup_allocate(uuid, uuid, uuid, uuid, text, timestamptz)",
    "signup_mark(uuid, text, timestamptz, timestamptz)",
    "signup_verify_queue(uuid, uuid, timestamptz)",
    "signup_verify_rekey(uuid, text, timestamptz)",
    "signup_verify_check(uuid, text, timestamptz)",
    "community_provision(uuid, text, uuid, uuid, uuid, text, text, jsonb, integer, timestamptz)",
)
# What the runtime held on the tables before this revision (0028, 0039, 0042, 0052 and 0054
# granted it), which the downgrade restores.
TABLE_GRANTS = (
    "SELECT ON execbound.community_allocations",
    "SELECT ON execbound.product_counts",
    "SELECT ON execbound.onboarding_slots",
    "SELECT (tenant_id, invitation_id, note, issued_at, expires_at, redeemed_at, revoked_at, "
    "failure_count) ON execbound.onboarding_invitations",
    "SELECT ON execbound.signup_requests",
    "SELECT ON execbound.signup_messages",
    "UPDATE (state, attempts, next_attempt_at, lease_until, lease_token, delivered_at, "
    "last_error) ON execbound.signup_messages",
    "SELECT ON execbound.account_preferences",
)
SUPABASE_ROLES = ("anon", "authenticated", "service_role")


def role_exists(role: str) -> bool:
    return bool(
        op.get_bind()
        .execute(text("SELECT 1 FROM pg_roles WHERE rolname = :role"), {"role": role})
        .scalar()
    )


def upgrade() -> None:
    roles = [role for role in SUPABASE_ROLES if role_exists(role)]
    # Revoking a table's privileges revokes its column privileges too.
    for table in TABLES:
        op.execute(f"REVOKE ALL ON execbound.{table} FROM PUBLIC, execbound_app")
        for role in roles:
            op.execute(f"REVOKE ALL ON execbound.{table} FROM {role}")
    for signature in FUNCTIONS:
        op.execute(f"REVOKE ALL ON FUNCTION execbound.{signature} FROM PUBLIC, execbound_app")
        for role in roles:
            op.execute(f"REVOKE ALL ON FUNCTION execbound.{signature} FROM {role}")


def downgrade() -> None:
    for grant in TABLE_GRANTS:
        op.execute(f"GRANT {grant} TO execbound_app")
    for signature in FUNCTIONS:
        op.execute(f"GRANT EXECUTE ON FUNCTION execbound.{signature} TO execbound_app")
