"""The sandbox claim stamps redemption and claim from the database clock.

0028 stamped ``redeemed_at`` and ``claimed_at`` with the caller's issue time, which the slot
and invitation check constraints compare against times other clocks wrote (the operator's
workstation at mint, the seeder at seed). A gateway clock a few seconds behind either made
an honest claim fail its constraint. The function body is otherwise unchanged, and so are
its signature, ownership and grants.
"""

from alembic import op

revision = "0029_claim_clock"
down_revision = "0028_onboarding"
branch_labels = None
depends_on = None


def _claim(redeemed_at: str, claimed_at: str) -> str:
    return rf"""
CREATE OR REPLACE FUNCTION execbound.onboarding_claim(
    p_invitation uuid, p_token_hash text, p_name text, p_admin uuid, p_credential uuid,
    p_credential_hash text, p_issued_at timestamptz, p_expires_at timestamptz)
RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_invitation execbound.onboarding_invitations%ROWTYPE;
    v_name text;
BEGIN
    IF v_tenant IS NULL OR p_invitation IS NULL THEN
        RAISE EXCEPTION 'INVALID_INVITATION';
    END IF;
    SELECT * INTO v_invitation FROM execbound.onboarding_invitations i
     WHERE i.tenant_id = v_tenant AND i.invitation_id = p_invitation FOR UPDATE;
    IF NOT FOUND OR v_invitation.revoked_at IS NOT NULL OR v_invitation.redeemed_at IS NOT NULL
       OR v_invitation.expires_at <= now() THEN
        RAISE EXCEPTION 'INVALID_INVITATION';
    END IF;
    IF p_token_hash IS NULL OR p_token_hash !~ '^[0-9a-f]{{64}}$'
       OR v_invitation.token_hash <> p_token_hash THEN
        UPDATE execbound.onboarding_invitations
           SET failure_count = failure_count + 1,
               revoked_at = CASE WHEN failure_count + 1 >= 5 THEN now() ELSE revoked_at END
         WHERE tenant_id = v_tenant AND invitation_id = p_invitation;
        RETURN NULL;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM execbound.tenants t WHERE t.tenant_id = v_tenant AND NOT t.active
    ) OR NOT EXISTS (
        SELECT 1 FROM execbound.onboarding_slots s
        WHERE s.tenant_id = v_tenant AND s.claimed_at IS NULL
    ) THEN
        RAISE EXCEPTION 'INVALID_SLOT';
    END IF;
    v_name := btrim(regexp_replace(coalesce(p_name, ''), '\s+', ' ', 'g'));
    IF v_name = '' OR length(v_name) > 120 THEN
        RAISE EXCEPTION 'INVALID_NAME';
    END IF;
    IF p_admin IS NULL OR p_credential IS NULL OR p_credential_hash IS NULL
       OR p_credential_hash !~ '^[0-9a-f]{{64}}$' THEN
        RAISE EXCEPTION 'INVALID_DIGEST';
    END IF;
    IF p_issued_at IS NULL OR abs(extract(epoch FROM (p_issued_at - now()))) > 300 THEN
        RAISE EXCEPTION 'INVALID_CLOCK';
    END IF;
    IF p_expires_at IS NULL
       OR p_expires_at - p_issued_at < interval '1 minute'
       OR p_expires_at - p_issued_at > interval '90 days' THEN
        RAISE EXCEPTION 'INVALID_LIFETIME';
    END IF;
    BEGIN
        UPDATE execbound.tenants SET name = v_name, active = true WHERE tenant_id = v_tenant;
    EXCEPTION WHEN unique_violation THEN
        RAISE EXCEPTION 'NAME_TAKEN';
    END;
    INSERT INTO execbound.principals (tenant_id, principal_id, kind)
    VALUES (v_tenant, p_admin, 'ADMIN');
    INSERT INTO execbound.credentials
        (tenant_id, credential_id, principal_id, token_hash, issued_at, expires_at)
    VALUES (v_tenant, p_credential, p_admin, p_credential_hash, p_issued_at, p_expires_at);
    UPDATE execbound.onboarding_invitations SET redeemed_at = {redeemed_at}
     WHERE tenant_id = v_tenant AND invitation_id = p_invitation;
    UPDATE execbound.onboarding_slots SET claimed_at = {claimed_at} WHERE tenant_id = v_tenant;
    RETURN v_tenant;
END $$
"""


def upgrade() -> None:
    op.execute(_claim("now()", "now()"))


def downgrade() -> None:
    op.execute(_claim("p_issued_at", "p_issued_at"))
