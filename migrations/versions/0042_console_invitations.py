"""Minting a sandbox invitation from the console: revocation, and reading the pool.

Two things the console needs that no earlier migration gives it, both small.

`onboarding_invitation_revoke` ends an invitation that has not been redeemed, under the slot's
fence with no actor: the authority is the operator's configuration, exactly as it is for
`onboarding_invite` of `0039_signups`, because there is no principal in a slot tenant for a
function to check. A revoke is what frees the slot for the next mint; rekeying the hash to a
digest nobody holds would leave a code that cannot be redeemed and a row the partial unique
index of `0028_onboarding` still counts as live.

The runtime then gains a **column-level** `SELECT` on `onboarding_invitations` naming every
column but `token_hash`, so the console can list the pool. The digest is not the code and is
not invertible, but the runtime holds what it needs and not one column more, and a test asserts
the refusal rather than leaving it as a comment.

Design: docs/superpowers/specs/2026-09-16-sandbox-onboarding-design.md, "Minting an invitation
from the console, September 20, 2026".
"""

from alembic import op

revision = "0042_console_invitations"
down_revision = "0041_spaces"
branch_labels = None
depends_on = None

SIGNATURE = "onboarding_invitation_revoke(uuid)"
# Every column of the table except the digest. Named one by one rather than taken from the
# catalog, so a column added later is not granted by accident.
READABLE = (
    "tenant_id",
    "invitation_id",
    "note",
    "issued_at",
    "expires_at",
    "redeemed_at",
    "revoked_at",
    "failure_count",
)

REVOKE_FN = r"""
CREATE FUNCTION execbound.onboarding_invitation_revoke(p_invitation uuid)
RETURNS timestamptz
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_invitation execbound.onboarding_invitations%ROWTYPE;
    v_now timestamptz := now();
BEGIN
    IF v_tenant IS NULL OR p_invitation IS NULL THEN
        RAISE EXCEPTION 'INVALID_INVITATION';
    END IF;
    SELECT * INTO v_invitation FROM execbound.onboarding_invitations i
     WHERE i.tenant_id = v_tenant AND i.invitation_id = p_invitation FOR UPDATE;
    -- A redeemed invitation is history: the slot is claimed and revoking would say something
    -- untrue about a tenant that exists. An already revoked one is not an error worth a second
    -- state, but it is not this call's doing either, so it is refused rather than reported.
    IF NOT FOUND OR v_invitation.redeemed_at IS NOT NULL
       OR v_invitation.revoked_at IS NOT NULL THEN
        RAISE EXCEPTION 'INVALID_INVITATION';
    END IF;
    UPDATE execbound.onboarding_invitations SET revoked_at = v_now
     WHERE tenant_id = v_tenant AND invitation_id = p_invitation;
    RETURN v_now;
END $$
"""


def upgrade() -> None:
    op.execute(REVOKE_FN)
    op.execute(f"GRANT EXECUTE ON FUNCTION execbound.{SIGNATURE} TO execbound_app")
    op.execute(
        "GRANT SELECT ("
        + ", ".join(READABLE)
        + ") ON execbound.onboarding_invitations TO execbound_app"
    )


def downgrade() -> None:
    op.execute(
        "REVOKE SELECT ("
        + ", ".join(READABLE)
        + ") ON execbound.onboarding_invitations FROM execbound_app"
    )
    op.execute(f"DROP FUNCTION execbound.{SIGNATURE}")
