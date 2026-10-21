# SPDX-License-Identifier: AGPL-3.0-only
"""The directory recheck claim gets its own column, and every writer the app's clock (#863).

0100 made one request of several the one that rechecks a directory session by moving
`federated_sign_ins.verified_at` from the value it read. The other requests then read a fresh
verification and were served while the directory had not yet answered, and the claim and the
recheck stamped the database's `now()` where the sign-in stamps the application's clock.

* `recheck_claimed_at`, nullable, holds the claim. `verified_at` now moves only on the
  directory's yes, so a request that finds the claim taken reads the verification as it was.
* `directory_recheck_claim(p_credential, p_seen, p_now)` replaces the two-argument claim. It
  sets `recheck_claimed_at` to `p_now` when `verified_at` still reads `p_seen` and no other
  claim stands, one older than sixty seconds (`directory_store.CLAIM_LEASE`) counting as none,
  so a request that died holding it cannot hold it for ever. It answers the claim, or NULL.
* `directory_recheck_release(p_credential, p_claimed)` replaces the three-argument release: it
  clears the claim, and only the claim it names, leaving `verified_at` as it was.
* `directory_recheck(p_credential, p_refresh_ciphertext, p_refresh_key_id, p_now, p_claimed)`
  replaces 0043's four-argument recheck. It records the directory's yes, `verified_at` stamped
  with `p_now` instead of `now()`, a rotated refresh token and the claim cleared, only while
  `recheck_claimed_at` still holds the caller's claim, and refuses `INVALID_CREDENTIAL`
  otherwise. A directory call that outlived its claim's lease therefore cannot clear the claim
  the next request took over or overwrite the refresh token that request stored.

All three are definers for the runtime role alone, as 0043's and 0100's were.

The downgrade drops the column and restores 0100's two functions and 0043's `directory_recheck`
as they were, with their grants. A claim standing at that moment is simply forgotten, which is
what a request that died holding one leaves behind.
"""

from alembic import op
from sqlalchemy import text

revision = "0102_directory_recheck_claim"
down_revision = "0101_trusted_browsers"
branch_labels = None
depends_on = None

SUPABASE_ROLES = ("anon", "authenticated", "service_role")

CLAIM = "directory_recheck_claim(uuid, timestamptz, timestamptz)"
RELEASE = "directory_recheck_release(uuid, timestamptz)"
CREATE_CLAIM = """
CREATE FUNCTION execbound.directory_recheck_claim(
    p_credential uuid, p_seen timestamptz, p_now timestamptz)
RETURNS timestamptz
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_claimed timestamptz;
BEGIN
    IF v_tenant IS NULL THEN
        RAISE EXCEPTION 'INVALID_TENANT';
    END IF;
    UPDATE execbound.federated_sign_ins
       SET recheck_claimed_at = p_now
     WHERE tenant_id = v_tenant AND credential_id = p_credential
       AND revoked_reason IS NULL AND verified_at = p_seen
       AND (recheck_claimed_at IS NULL OR recheck_claimed_at <= p_now - interval '60 seconds')
    RETURNING recheck_claimed_at INTO v_claimed;
    RETURN v_claimed;
END $$
"""
CREATE_RELEASE = """
CREATE FUNCTION execbound.directory_recheck_release(p_credential uuid, p_claimed timestamptz)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
BEGIN
    IF v_tenant IS NULL THEN
        RAISE EXCEPTION 'INVALID_TENANT';
    END IF;
    UPDATE execbound.federated_sign_ins
       SET recheck_claimed_at = NULL
     WHERE tenant_id = v_tenant AND credential_id = p_credential
       AND recheck_claimed_at = p_claimed;
END $$
"""
RECHECK = "directory_recheck(uuid, text, text, timestamptz, timestamptz)"
CREATE_RECHECK = """
CREATE FUNCTION execbound.directory_recheck(
    p_credential uuid, p_refresh_ciphertext text, p_refresh_key_id text, p_now timestamptz,
    p_claimed timestamptz)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
BEGIN
    IF v_tenant IS NULL THEN
        RAISE EXCEPTION 'INVALID_TENANT';
    END IF;
    UPDATE execbound.federated_sign_ins
       SET verified_at = p_now,
           recheck_claimed_at = NULL,
           refresh_ciphertext = coalesce(p_refresh_ciphertext, refresh_ciphertext),
           refresh_key_id = coalesce(p_refresh_key_id, refresh_key_id)
     WHERE tenant_id = v_tenant AND credential_id = p_credential AND revoked_reason IS NULL
       AND recheck_claimed_at = p_claimed;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'INVALID_CREDENTIAL';
    END IF;
END $$
"""

# 0043's recheck and 0100's two functions, restored by the downgrade exactly as they were created.
OLD_RECHECK = "directory_recheck(uuid, text, text, timestamptz)"
OLD_CREATE_RECHECK = """
CREATE FUNCTION execbound.directory_recheck(
    p_credential uuid, p_refresh_ciphertext text, p_refresh_key_id text, p_now timestamptz)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
BEGIN
    IF v_tenant IS NULL THEN
        RAISE EXCEPTION 'INVALID_TENANT';
    END IF;
    UPDATE execbound.federated_sign_ins
       SET verified_at = now(),
           refresh_ciphertext = coalesce(p_refresh_ciphertext, refresh_ciphertext),
           refresh_key_id = coalesce(p_refresh_key_id, refresh_key_id)
     WHERE tenant_id = v_tenant AND credential_id = p_credential AND revoked_reason IS NULL;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'INVALID_CREDENTIAL';
    END IF;
END $$
"""
OLD_CLAIM = "directory_recheck_claim(uuid, timestamptz)"
OLD_RELEASE = "directory_recheck_release(uuid, timestamptz, timestamptz)"
OLD_CREATE_CLAIM = """
CREATE FUNCTION execbound.directory_recheck_claim(p_credential uuid, p_seen timestamptz)
RETURNS timestamptz
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_claimed timestamptz;
BEGIN
    IF v_tenant IS NULL THEN
        RAISE EXCEPTION 'INVALID_TENANT';
    END IF;
    UPDATE execbound.federated_sign_ins
       SET verified_at = now()
     WHERE tenant_id = v_tenant AND credential_id = p_credential
       AND revoked_reason IS NULL AND verified_at = p_seen
    RETURNING verified_at INTO v_claimed;
    RETURN v_claimed;
END $$
"""
OLD_CREATE_RELEASE = """
CREATE FUNCTION execbound.directory_recheck_release(
    p_credential uuid, p_claimed timestamptz, p_seen timestamptz)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
BEGIN
    IF v_tenant IS NULL THEN
        RAISE EXCEPTION 'INVALID_TENANT';
    END IF;
    UPDATE execbound.federated_sign_ins
       SET verified_at = p_seen
     WHERE tenant_id = v_tenant AND credential_id = p_credential
       AND revoked_reason IS NULL AND verified_at = p_claimed;
END $$
"""


def _role_exists(role: str) -> bool:
    return bool(
        op.get_bind()
        .execute(text("SELECT 1 FROM pg_roles WHERE rolname = :role"), {"role": role})
        .scalar()
    )


def _create(body: str, signature: str) -> None:
    op.execute(body)
    op.execute(f"REVOKE ALL ON FUNCTION execbound.{signature} FROM PUBLIC")
    for role in SUPABASE_ROLES:
        if _role_exists(role):
            op.execute(f"REVOKE ALL ON FUNCTION execbound.{signature} FROM {role}")
    op.execute(f"GRANT EXECUTE ON FUNCTION execbound.{signature} TO execbound_app")


def upgrade() -> None:
    op.execute("ALTER TABLE execbound.federated_sign_ins ADD COLUMN recheck_claimed_at timestamptz")
    op.execute(f"DROP FUNCTION execbound.{OLD_RELEASE}")
    op.execute(f"DROP FUNCTION execbound.{OLD_CLAIM}")
    op.execute(f"DROP FUNCTION execbound.{OLD_RECHECK}")
    _create(CREATE_CLAIM, CLAIM)
    _create(CREATE_RELEASE, RELEASE)
    _create(CREATE_RECHECK, RECHECK)


def downgrade() -> None:
    op.execute(f"DROP FUNCTION execbound.{RECHECK}")
    op.execute(f"DROP FUNCTION execbound.{RELEASE}")
    op.execute(f"DROP FUNCTION execbound.{CLAIM}")
    _create(OLD_CREATE_CLAIM, OLD_CLAIM)
    _create(OLD_CREATE_RELEASE, OLD_RELEASE)
    _create(OLD_CREATE_RECHECK, OLD_RECHECK)
    op.execute("ALTER TABLE execbound.federated_sign_ins DROP COLUMN recheck_claimed_at")
