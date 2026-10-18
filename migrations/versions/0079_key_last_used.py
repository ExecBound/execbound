# SPDX-License-Identifier: AGPL-3.0-only
"""An agent key's last use, a recorded rotation, and who has a second factor.

Two nullable columns on `credentials`, both display and notice state only, and three definer
functions, each the only writer or reader of what it serves:

- `credential_used` stamps `last_used_at` when a key has passed every authentication check.
  Authentication calls it at most once a minute per key, inside a savepoint whose failure it
  ignores, so the stamp can never change whether a key authenticates. The function itself
  never fails on clock skew between the application and the database: a key's `issued_at` is
  the application's clock (`admin_issue_credential` accepts one up to 300 s from the
  database's), so a use earlier than `issued_at` stamps nothing instead of raising. It takes
  the row with `FOR NO KEY UPDATE SKIP LOCKED`, which does not conflict with the key-share
  locks that execution, approval and session inserts take through their foreign keys and
  never waits on a revocation or a concurrent stamp: a locked row is simply not stamped this
  time. The runtime role keeps no `UPDATE` on `credentials`.
- `admin_credential_replaces` records that a newly issued key replaces a live key of the same
  agent, in the issuing transaction, right after `admin_issue_credential`. A key is shown as
  replaced only when a live key names it here; nothing infers a replacement from a newer key,
  because an agent often holds several live keys for different integrations. It locks the old
  key's row first, so two rotations of one key cannot both name it, and refuses anything else
  with `INVALID_REPLACEMENT`, which rolls the whole issue back.
- `admin_member_factors` answers an active administrator one boolean per listed person: whether
  that person has an enabled second factor, read exactly as step-up enforcement reads it
  (`user_accounts.factor_account`, then `mfa._factor`). With a workspace membership, the factor
  is the membership account's row in `user_factors` and the legacy `account_factors` row is not
  read, so a stale enabled legacy row can never make a person look enrolled. `user_factors` is
  account-scoped under forced row security, and the owner of this function does not bypass row
  security on a managed host, so it reads each account by setting `execbound.account_id` to it
  and restores the caller's value afterwards, as `account_adopt` does.

There is deliberately no check constraint relating `last_used_at` to `issued_at`: they come
from different clocks, and a constraint violation inside authentication is exactly what the
stamp must never cause. `replaces_credential_id` has no foreign key, so inserting a key takes
no lock on the key it names; `admin_credential_replaces` is its only writer and checks the
reference. Neither column authorises, expires or revokes anything, so the downgrade drops both
along with the index and the three functions, and their loss is accepted.
"""

from alembic import op
from sqlalchemy import text

revision = "0079_key_last_used"
down_revision = "0078_weekly_summary"
branch_labels = None
depends_on = None

# The actor check of `admin_issue_personal_token` (0063): an active, non-agent principal of an
# active tenant whose effective kind is ADMIN.
ACTOR = """
    IF v_tenant IS NULL OR NOT EXISTS (
        SELECT 1 FROM execbound.tenants t WHERE t.tenant_id = v_tenant AND t.active
    ) THEN
        RAISE EXCEPTION 'INVALID_TENANT';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM execbound.principals p
         WHERE p.tenant_id = v_tenant AND p.principal_id = p_actor AND p.active
           AND p.kind <> 'AGENT' AND execbound.access_effective_kind(p_actor) = 'ADMIN'
    ) THEN
        RAISE EXCEPTION 'INVALID_ACTOR';
    END IF;
"""

USED = """
CREATE FUNCTION execbound.credential_used(p_credential uuid, p_used_at timestamptz)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
BEGIN
    IF v_tenant IS NULL THEN
        RAISE EXCEPTION 'INVALID_TENANT';
    END IF;
    IF p_used_at IS NULL OR abs(extract(epoch FROM (p_used_at - now()))) > 300 THEN
        RAISE EXCEPTION 'INVALID_CLOCK';
    END IF;
    -- A live key of this tenant, issued no later than this use, not stamped in the last
    -- minute. A row another transaction holds is skipped rather than waited for.
    UPDATE execbound.credentials AS c SET last_used_at = p_used_at
     WHERE c.tenant_id = v_tenant AND c.credential_id = (
        SELECT k.credential_id FROM execbound.credentials k
         WHERE k.tenant_id = v_tenant AND k.credential_id = p_credential
           AND k.revoked_at IS NULL AND k.deleted_at IS NULL
           AND k.expires_at > p_used_at AND p_used_at >= k.issued_at
           AND (k.last_used_at IS NULL OR k.last_used_at <= p_used_at - interval '1 minute')
           FOR NO KEY UPDATE SKIP LOCKED
     );
END $$
"""

# The narrowing of `admin_issue_credential` since 0071, read against the agent both keys
# belong to: a narrowed administrator links the keys of their own spaces' agents alone.
MAY_ADMINISTER = """(p.space_id IS NULL
           OR execbound.access_has_permission(p_actor,'access.manage',NULL,false)
           OR NOT EXISTS (
               SELECT 1 FROM execbound.space_members m
               WHERE m.tenant_id = v_tenant AND m.principal_id = p_actor
           )
           OR EXISTS (
               SELECT 1 FROM execbound.space_members m
               WHERE m.tenant_id = v_tenant AND m.principal_id = p_actor
                 AND m.space_id = p.space_id AND m.role = 'ADMIN'
           ))"""

REPLACES = f"""
CREATE FUNCTION execbound.admin_credential_replaces(
    p_actor uuid, p_credential uuid, p_replaces uuid)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_old uuid;
    v_new uuid;
BEGIN
    {ACTOR}
    IF p_credential IS NULL OR p_replaces IS NULL OR p_credential = p_replaces THEN
        RAISE EXCEPTION 'INVALID_REPLACEMENT';
    END IF;
    -- The old key first, so two rotations of one key serialize here.
    SELECT c.principal_id INTO v_old FROM execbound.credentials c
     WHERE c.tenant_id = v_tenant AND c.credential_id = p_replaces
       AND c.revoked_at IS NULL AND c.deleted_at IS NULL AND c.expires_at > now()
       FOR NO KEY UPDATE;
    SELECT c.principal_id INTO v_new FROM execbound.credentials c
     WHERE c.tenant_id = v_tenant AND c.credential_id = p_credential
       AND c.revoked_at IS NULL AND c.deleted_at IS NULL AND c.replaces_credential_id IS NULL
       FOR NO KEY UPDATE;
    IF v_old IS NULL OR v_new IS NULL OR v_old <> v_new THEN
        RAISE EXCEPTION 'INVALID_REPLACEMENT';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM execbound.principals p
         WHERE p.tenant_id = v_tenant AND p.principal_id = v_new AND p.kind = 'AGENT'
           AND {MAY_ADMINISTER}
    ) THEN
        RAISE EXCEPTION 'INVALID_REPLACEMENT';
    END IF;
    IF EXISTS (
        SELECT 1 FROM execbound.credentials c
         WHERE c.tenant_id = v_tenant AND c.replaces_credential_id = p_replaces
           AND c.credential_id <> p_credential
           AND c.revoked_at IS NULL AND c.deleted_at IS NULL AND c.expires_at > now()
    ) THEN
        RAISE EXCEPTION 'INVALID_REPLACEMENT';
    END IF;
    UPDATE execbound.credentials SET replaces_credential_id = p_replaces
     WHERE tenant_id = v_tenant AND credential_id = p_credential;
END $$
"""

# The limit is `people_pages.LIST_LIMIT`, the most people one page lists.
FACTORS = f"""
CREATE FUNCTION execbound.admin_member_factors(p_actor uuid, p_principals uuid[])
RETURNS TABLE(principal_id uuid, enrolled boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_saved text := coalesce(current_setting('execbound.account_id', true), '');
    v_person uuid;
    v_account uuid;
    v_enrolled boolean;
BEGIN
    {ACTOR}
    IF p_principals IS NULL OR cardinality(p_principals) > 500 THEN
        RAISE EXCEPTION 'INVALID_REQUEST';
    END IF;
    FOR v_person IN
        SELECT DISTINCT q.principal_id FROM execbound.principals q
         WHERE q.tenant_id = v_tenant AND q.principal_id = ANY(p_principals)
           AND q.kind IN ('ADMIN', 'HUMAN_APPROVER')
    LOOP
        -- As `user_accounts.factor_account` reads it: any membership row, active or not.
        v_account := NULL;
        SELECT w.account_id INTO v_account FROM execbound.workspace_memberships w
         WHERE w.tenant_id = v_tenant AND w.principal_id = v_person;
        IF v_account IS NOT NULL THEN
            PERFORM set_config('execbound.account_id', v_account::text, true);
            SELECT EXISTS (
                SELECT 1 FROM execbound.user_factors f
                 WHERE f.account_id = v_account AND f.enabled_at IS NOT NULL
            ) INTO v_enrolled;
        ELSE
            SELECT EXISTS (
                SELECT 1 FROM execbound.account_factors f
                 WHERE f.tenant_id = v_tenant AND f.principal_id = v_person
                   AND f.enabled_at IS NOT NULL
            ) INTO v_enrolled;
        END IF;
        principal_id := v_person;
        enrolled := v_enrolled;
        RETURN NEXT;
    END LOOP;
    PERFORM set_config('execbound.account_id', v_saved, true);
END $$
"""

SIGNATURES = (
    "credential_used(uuid, timestamptz)",
    "admin_credential_replaces(uuid, uuid, uuid)",
    "admin_member_factors(uuid, uuid[])",
)


def role_exists(role: str) -> bool:
    return bool(
        op.get_bind()
        .execute(text("SELECT 1 FROM pg_roles WHERE rolname = :role"), {"role": role})
        .scalar()
    )


def upgrade() -> None:
    op.execute("ALTER TABLE execbound.credentials ADD COLUMN last_used_at timestamptz")
    op.execute("ALTER TABLE execbound.credentials ADD COLUMN replaces_credential_id uuid")
    op.execute(
        "CREATE INDEX credentials_replaces_idx "
        "ON execbound.credentials (tenant_id, replaces_credential_id) "
        "WHERE replaces_credential_id IS NOT NULL"
    )
    for body in (USED, REPLACES, FACTORS):
        op.execute(body)
    for signature in SIGNATURES:
        op.execute(f"REVOKE ALL ON FUNCTION execbound.{signature} FROM PUBLIC")
        for role in ("anon", "authenticated", "service_role"):
            if role_exists(role):
                op.execute(f"REVOKE ALL ON FUNCTION execbound.{signature} FROM {role}")
        op.execute(f"GRANT EXECUTE ON FUNCTION execbound.{signature} TO execbound_app")


def downgrade() -> None:
    for signature in SIGNATURES:
        op.execute(f"DROP FUNCTION execbound.{signature}")
    op.execute("DROP INDEX execbound.credentials_replaces_idx")
    op.execute("ALTER TABLE execbound.credentials DROP COLUMN replaces_credential_id")
    op.execute("ALTER TABLE execbound.credentials DROP COLUMN last_used_at")
