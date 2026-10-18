"""Sandbox onboarding: pre-seeded slots, single-use invitations, the claim and the refresher.

A slot is an inactive tenant the operator seeded in a batch; an invitation is an operator-minted
code that activates exactly one slot once. The runtime role gains EXECUTE on two functions and
SELECT on the slots table, and no table write privilege: the claim writes the tenant, its first
ADMIN and that ADMIN's credential inside the database, and the refresher re-stamps a claimed
sandbox's facts and reconciles each target's expected provider version from the tenant's own
retained receipts.
"""

from alembic import op
from sqlalchemy import text

revision = "0028_onboarding"
down_revision = "0027_approval_deadline"
branch_labels = None
depends_on = None

TENANT = "nullif((SELECT current_setting('execbound.tenant_id', true)), '')::uuid"
SEED = "^[A-Za-z0-9_-]{1,80}$"
DIGEST = "^[0-9a-f]{64}$"
SIGNATURES = (
    "onboarding_claim(uuid, text, text, uuid, uuid, text, timestamptz, timestamptz)",
    "sandbox_reattest(uuid)",
)

# The claim is one transaction over the one tenant the fence names. Authority comes from the
# invitation, which only the owner connection can mint, so no acting ADMIN is required: the
# tenant has none until this function creates it. A secret mismatch is the one refusal that
# must leave a mark, and a RAISE would roll that mark back with everything else, so the
# function counts it, revokes the invitation on the fifth, and answers NULL; every other
# refusal raises its code and writes nothing. After a successful claim the tenant is active
# and the slot is claimed, so the same function can never touch that tenant again.
CLAIM = r"""
CREATE FUNCTION execbound.onboarding_claim(
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
    IF p_token_hash IS NULL OR p_token_hash !~ '^[0-9a-f]{64}$'
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
       OR p_credential_hash !~ '^[0-9a-f]{64}$' THEN
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
    UPDATE execbound.onboarding_invitations SET redeemed_at = p_issued_at
     WHERE tenant_id = v_tenant AND invitation_id = p_invitation;
    UPDATE execbound.onboarding_slots SET claimed_at = p_issued_at WHERE tenant_id = v_tenant;
    RETURN v_tenant;
END $$
"""

# The sandbox's stand-in for an inventory sync. Only a claimed sandbox, only for an active
# ADMIN of it, only forward: every fact keeps its value and gets a fresh observation time,
# and a target that the tenant's own agent changed takes the version the provider's signed
# receipt reported, which is what a real tenant's inventory sync would report next. The
# receipt is the retained evidence of the latest EXECUTED operation ExecBound dispatched to
# that target (a checkpoint grant settles at a tier and is not one); nothing is read from a
# caller or from the provider.
REATTEST = """
CREATE FUNCTION execbound.sandbox_reattest(p_actor uuid)
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_count integer;
BEGIN
    IF v_tenant IS NULL OR NOT EXISTS (
        SELECT 1 FROM execbound.tenants t WHERE t.tenant_id = v_tenant AND t.active
    ) OR NOT EXISTS (
        SELECT 1 FROM execbound.onboarding_slots s
        WHERE s.tenant_id = v_tenant AND s.claimed_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'INVALID_SLOT';
    END IF;
    IF p_actor IS NULL OR NOT EXISTS (
        SELECT 1 FROM execbound.principals p
        WHERE p.tenant_id = v_tenant AND p.principal_id = p_actor
          AND p.active AND p.kind = 'ADMIN'
    ) THEN
        RAISE EXCEPTION 'INVALID_ACTOR';
    END IF;
    UPDATE execbound.resources r
       SET observed_at = now(),
           version = coalesce(v.resulting_version, r.version)
      FROM (
        SELECT r2.account_id, r2.provider, r2.resource_type, r2.resource_id,
               (SELECT (e.result ->> 'authenticated_record')::jsonb
                           #>> '{record,resulting_version}'
                  FROM execbound.executions e
                 WHERE e.tenant_id = v_tenant
                   AND e.canonical_target_id = i.canonical_target_id
                   AND e.state = 'EXECUTED' AND e.settlement_tier IS NULL
                   AND e.result ? 'authenticated_record'
                 ORDER BY e.changed_at DESC, e.execution_id DESC
                 LIMIT 1) AS resulting_version
          FROM execbound.resources r2
          LEFT JOIN execbound.resource_identities i
            USING (tenant_id, account_id, provider, resource_type, resource_id)
         WHERE r2.tenant_id = v_tenant) v
     WHERE r.tenant_id = v_tenant AND r.account_id = v.account_id AND r.provider = v.provider
       AND r.resource_type = v.resource_type AND r.resource_id = v.resource_id;
    GET DIAGNOSTICS v_count = ROW_COUNT;
    UPDATE execbound.resource_facts SET observed_at = now() WHERE tenant_id = v_tenant;
    UPDATE execbound.incidents SET observed_at = now() WHERE tenant_id = v_tenant;
    RETURN v_count;
END $$
"""


def _lift_rls(tables: tuple[str, ...]) -> None:
    op.execute(
        "LOCK TABLE " + ", ".join(f"execbound.{t}" for t in tables) + " IN ACCESS EXCLUSIVE MODE"
    )
    for table in tables:
        op.execute(f"ALTER TABLE execbound.{table} NO FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security = off")


def _restore_rls(tables: tuple[str, ...]) -> None:
    for table in tables:
        op.execute(f"ALTER TABLE execbound.{table} FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security = on")


def _protect(table: str) -> None:
    op.execute(f"ALTER TABLE execbound.{table} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE execbound.{table} FORCE ROW LEVEL SECURITY")
    op.execute(f"""
        CREATE POLICY tenant_isolation ON execbound.{table}
        USING (tenant_id = {TENANT}) WITH CHECK (tenant_id = {TENANT})
    """)
    for role in ("PUBLIC", "anon", "authenticated", "service_role", "execbound_app"):
        if (
            role != "PUBLIC"
            and not op.get_bind()
            .execute(text("SELECT 1 FROM pg_roles WHERE rolname = :role"), {"role": role})
            .scalar()
        ):
            continue
        op.execute(f"REVOKE ALL ON execbound.{table} FROM {role}")


def upgrade() -> None:
    op.execute(f"""
        CREATE TABLE execbound.onboarding_slots (
            tenant_id uuid PRIMARY KEY REFERENCES execbound.tenants,
            slot integer NOT NULL CHECK (slot >= 1),
            seed text NOT NULL CHECK (seed ~ '{SEED}'),
            seeded_at timestamptz NOT NULL,
            claimed_at timestamptz CHECK (claimed_at IS NULL OR claimed_at >= seeded_at),
            UNIQUE (seed, slot)
        )
    """)
    _protect("onboarding_slots")
    # The welcome page and the refresher read a tenant's own slot row; nothing writes it
    # from the runtime except the claim function.
    op.execute("GRANT SELECT ON execbound.onboarding_slots TO execbound_app")
    op.execute(f"""
        CREATE TABLE execbound.onboarding_invitations (
            tenant_id uuid NOT NULL REFERENCES execbound.onboarding_slots,
            invitation_id uuid NOT NULL,
            token_hash text NOT NULL CHECK (token_hash ~ '{DIGEST}'),
            note text NOT NULL CHECK (length(note) BETWEEN 1 AND 200),
            issued_at timestamptz NOT NULL,
            expires_at timestamptz NOT NULL CHECK (expires_at > issued_at),
            redeemed_at timestamptz CHECK (redeemed_at IS NULL OR redeemed_at >= issued_at),
            revoked_at timestamptz CHECK (revoked_at IS NULL OR revoked_at >= issued_at),
            failure_count integer NOT NULL DEFAULT 0 CHECK (failure_count BETWEEN 0 AND 5),
            PRIMARY KEY (tenant_id, invitation_id)
        )
    """)
    _protect("onboarding_invitations")
    # A slot has at most one invitation that is neither redeemed nor revoked; the owner
    # tooling revokes an expired one before minting the next.
    op.execute(
        "CREATE UNIQUE INDEX onboarding_invitations_live "
        "ON execbound.onboarding_invitations (tenant_id) "
        "WHERE redeemed_at IS NULL AND revoked_at IS NULL"
    )
    # Tenant names become unique case-insensitively; a claimed sandbox's name must not
    # collide with any other tenant's, and the claim reports that collision as NAME_TAKEN.
    # The guard reads every tenant, so RLS is lifted on the table for the transaction and
    # restored before it ends; a collision is the operator's to resolve, by name.
    _lift_rls(("tenants",))
    collisions = (
        op.get_bind()
        .execute(
            text(
                "SELECT lower(name) FROM execbound.tenants GROUP BY lower(name) HAVING count(*) > 1"
            )
        )
        .scalars()
        .all()
    )
    if collisions:
        raise RuntimeError(
            "Cannot upgrade while tenant names collide case-insensitively: "
            + ", ".join(sorted(collisions))
        )
    _restore_rls(("tenants",))
    op.execute("CREATE UNIQUE INDEX tenants_name_lower ON execbound.tenants (lower(name))")
    for body in (CLAIM, REATTEST):
        op.execute(body)
    for signature in SIGNATURES:
        op.execute(f"REVOKE ALL ON FUNCTION execbound.{signature} FROM PUBLIC")
        for role in ("anon", "authenticated", "service_role"):
            if (
                op.get_bind()
                .execute(text("SELECT 1 FROM pg_roles WHERE rolname = :role"), {"role": role})
                .scalar()
            ):
                op.execute(f"REVOKE ALL ON FUNCTION execbound.{signature} FROM {role}")
        op.execute(f"GRANT EXECUTE ON FUNCTION execbound.{signature} TO execbound_app")


def downgrade() -> None:
    # A claimed sandbox is an ordinary active tenant once its slot row is gone; an unclaimed
    # slot stays an inactive tenant nothing can reach. Neither loses history.
    for signature in SIGNATURES:
        op.execute(f"DROP FUNCTION execbound.{signature}")
    op.execute("DROP INDEX execbound.tenants_name_lower")
    op.execute("DROP TABLE execbound.onboarding_invitations")
    op.execute("DROP TABLE execbound.onboarding_slots")
