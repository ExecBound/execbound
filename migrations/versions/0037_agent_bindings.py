"""Agent bindings: which governed AGENT principal a discovered agent is, said explicitly.

A binding joins one agent a monitoring connection lists to one active AGENT principal of the
same tenant, records who bound it and when, and is never deleted: unbinding stamps the row
with who, when and why. Partial unique indexes keep an active binding one to one.

Scout's reach derivation already reads ``monitor_agents.linked_principal_id``. The two
SECURITY DEFINER functions here are now the only way that column changes: binding sets it
and unbinding clears it in the same statement sequence, and the runtime role loses its
``UPDATE`` on the column. Unbinding also marks the agent's ExecBound-path reach rows for that
principal gone at once, because the link they rested on no longer exists.

Links made before this table existed become bindings when they join an active AGENT
principal (the earliest collected agent per principal, with no ``bound_by``); any other link
was never allowed by the design and is cleared.
"""

from alembic import op
from sqlalchemy import text

revision = "0037_agent_bindings"
down_revision = "0036_people"
branch_labels = None
depends_on = None

SIGNATURES = (
    "admin_bind_agent(uuid, uuid, uuid)",
    "admin_unbind_agent(uuid, uuid, text)",
)

# The 0021 preamble, restated: the tenant comes from the fence setting; the actor must be an
# active ADMIN of that active tenant.
ACTOR_CHECK = """
    IF v_tenant IS NULL THEN
        RAISE EXCEPTION 'INVALID_TENANT';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM execbound.tenants t WHERE t.tenant_id = v_tenant AND t.active
    ) THEN
        RAISE EXCEPTION 'INVALID_TENANT';
    END IF;
    IF p_actor IS NULL OR NOT EXISTS (
        SELECT 1 FROM execbound.principals p
        WHERE p.tenant_id = v_tenant AND p.principal_id = p_actor
          AND p.active AND p.kind = 'ADMIN'
    ) THEN
        RAISE EXCEPTION 'INVALID_ACTOR';
    END IF;
"""

FUNCTIONS = (
    f"""
CREATE FUNCTION execbound.admin_bind_agent(p_actor uuid, p_agent uuid, p_principal uuid)
RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_binding uuid := gen_random_uuid();
BEGIN
    {ACTOR_CHECK}
    PERFORM 1 FROM execbound.principals p
    WHERE p.tenant_id = v_tenant AND p.principal_id = p_principal
      AND p.kind = 'AGENT' AND p.active
    FOR SHARE;
    IF p_principal IS NULL OR NOT FOUND THEN
        RAISE EXCEPTION 'INVALID_PRINCIPAL';
    END IF;
    PERFORM 1 FROM execbound.monitor_agents a
    WHERE a.tenant_id = v_tenant AND a.agent_id = p_agent AND a.gone_at IS NULL
    FOR UPDATE;
    IF p_agent IS NULL OR NOT FOUND THEN
        RAISE EXCEPTION 'INVALID_AGENT';
    END IF;
    IF EXISTS (
        SELECT 1 FROM execbound.agent_bindings b
        WHERE b.tenant_id = v_tenant AND b.unbound_at IS NULL
          AND (b.agent_id = p_agent OR b.principal_id = p_principal)
    ) THEN
        RAISE EXCEPTION 'INVALID_STATE';
    END IF;
    INSERT INTO execbound.agent_bindings
        (tenant_id, binding_id, agent_id, principal_id, bound_by, bound_at)
    VALUES (v_tenant, v_binding, p_agent, p_principal, p_actor, now());
    UPDATE execbound.monitor_agents SET linked_principal_id = p_principal
    WHERE tenant_id = v_tenant AND agent_id = p_agent;
    RETURN v_binding;
EXCEPTION WHEN unique_violation THEN
    -- Two binds racing for one agent or one principal: the index decides, the loser is told.
    RAISE EXCEPTION 'INVALID_STATE';
END $$
""",
    f"""
CREATE FUNCTION execbound.admin_unbind_agent(p_actor uuid, p_binding uuid, p_reason text)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_reason text := btrim(p_reason);
    v_agent uuid;
    v_principal uuid;
BEGIN
    {ACTOR_CHECK}
    IF v_reason IS NULL OR char_length(v_reason) < 1 OR char_length(v_reason) > 500 THEN
        RAISE EXCEPTION 'INVALID_REASON';
    END IF;
    UPDATE execbound.agent_bindings
    SET unbound_at = now(), unbound_by = p_actor, unbound_reason = v_reason
    WHERE tenant_id = v_tenant AND binding_id = p_binding AND unbound_at IS NULL
    RETURNING agent_id, principal_id INTO v_agent, v_principal;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'INVALID_STATE';
    END IF;
    UPDATE execbound.monitor_agents SET linked_principal_id = NULL
    WHERE tenant_id = v_tenant AND agent_id = v_agent;
    -- The ExecBound path rested on the link just withdrawn; it stops being a live claim now
    -- rather than at the next derivation. Binding again and deriving revive the rows.
    UPDATE execbound.monitor_agent_reach SET gone_at = greatest(now(), computed_at)
    WHERE tenant_id = v_tenant AND agent_id = v_agent AND path_kind = 'execbound'
      AND path_ref = v_principal::text AND gone_at IS NULL;
    RETURN jsonb_build_object('agent_id', v_agent, 'principal_id', v_principal);
END $$
""",
)


def _grant_functions() -> None:
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


def upgrade() -> None:
    op.execute("""
        CREATE TABLE execbound.agent_bindings (
            tenant_id uuid NOT NULL REFERENCES execbound.tenants,
            binding_id uuid NOT NULL,
            agent_id uuid NOT NULL,
            principal_id uuid NOT NULL,
            bound_by uuid,
            bound_at timestamptz NOT NULL,
            unbound_at timestamptz,
            unbound_by uuid,
            unbound_reason text
                CHECK (unbound_reason IS NULL OR char_length(unbound_reason) BETWEEN 1 AND 500),
            PRIMARY KEY (tenant_id, binding_id),
            FOREIGN KEY (tenant_id, agent_id)
                REFERENCES execbound.monitor_agents (tenant_id, agent_id),
            FOREIGN KEY (tenant_id, principal_id)
                REFERENCES execbound.principals (tenant_id, principal_id),
            FOREIGN KEY (tenant_id, bound_by)
                REFERENCES execbound.principals (tenant_id, principal_id),
            FOREIGN KEY (tenant_id, unbound_by)
                REFERENCES execbound.principals (tenant_id, principal_id),
            CHECK ((unbound_at IS NULL) = (unbound_by IS NULL)),
            CHECK ((unbound_at IS NULL) = (unbound_reason IS NULL)),
            CHECK (unbound_at IS NULL OR unbound_at >= bound_at)
        )
    """)
    op.execute(
        "CREATE UNIQUE INDEX agent_bindings_active_agent "
        "ON execbound.agent_bindings (tenant_id, agent_id) WHERE unbound_at IS NULL"
    )
    op.execute(
        "CREATE UNIQUE INDEX agent_bindings_active_principal "
        "ON execbound.agent_bindings (tenant_id, principal_id) WHERE unbound_at IS NULL"
    )
    # Every foreign key has a covering index of its own; the partial ones above cover only
    # the active rows.
    for column in ("agent_id", "principal_id", "bound_by", "unbound_by"):
        op.execute(
            f"CREATE INDEX agent_bindings_{column} "
            f"ON execbound.agent_bindings (tenant_id, {column})"
        )
    # The backfill reads every tenant's links, so it runs before the new table's policy
    # exists and with the agents table briefly not forcing its policy on its owner.
    op.execute("ALTER TABLE execbound.monitor_agents NO FORCE ROW LEVEL SECURITY")
    op.execute("""
        INSERT INTO execbound.agent_bindings
            (tenant_id, binding_id, agent_id, principal_id, bound_by, bound_at)
        SELECT ranked.tenant_id, gen_random_uuid(), ranked.agent_id,
               ranked.linked_principal_id, NULL, now()
        FROM (
            SELECT a.tenant_id, a.agent_id, a.linked_principal_id,
                   row_number() OVER (
                       PARTITION BY a.tenant_id, a.linked_principal_id
                       ORDER BY a.first_seen_at, a.agent_id
                   ) AS position
            FROM execbound.monitor_agents a
            JOIN execbound.principals p
              ON p.tenant_id = a.tenant_id AND p.principal_id = a.linked_principal_id
            WHERE a.linked_principal_id IS NOT NULL AND a.gone_at IS NULL
              AND p.kind = 'AGENT' AND p.active
        ) ranked
        WHERE ranked.position = 1
    """)
    op.execute("""
        UPDATE execbound.monitor_agents a SET linked_principal_id = NULL
        WHERE a.linked_principal_id IS NOT NULL AND NOT EXISTS (
            SELECT 1 FROM execbound.agent_bindings b
            WHERE b.tenant_id = a.tenant_id AND b.agent_id = a.agent_id
              AND b.unbound_at IS NULL
        )
    """)
    op.execute("ALTER TABLE execbound.monitor_agents FORCE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE execbound.agent_bindings ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE execbound.agent_bindings FORCE ROW LEVEL SECURITY")
    op.execute("""
        CREATE POLICY tenant_isolation ON execbound.agent_bindings
        USING (tenant_id = nullif(
            (SELECT current_setting('execbound.tenant_id', true)), ''
        )::uuid)
        WITH CHECK (tenant_id = nullif(
            (SELECT current_setting('execbound.tenant_id', true)), ''
        )::uuid)
    """)
    op.execute("REVOKE ALL ON execbound.agent_bindings FROM PUBLIC")
    for role in ("anon", "authenticated", "service_role", "execbound_app"):
        if (
            op.get_bind()
            .execute(
                text("SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :role)"),
                {"role": role},
            )
            .scalar_one()
        ):
            op.execute(f"REVOKE ALL ON execbound.agent_bindings FROM {role}")
    op.execute("GRANT SELECT ON execbound.agent_bindings TO execbound_app")
    # The functions below are now the only writers of the link.
    op.execute("REVOKE UPDATE (linked_principal_id) ON execbound.monitor_agents FROM execbound_app")
    for body in FUNCTIONS:
        op.execute(body)
    _grant_functions()


def downgrade() -> None:
    op.execute("LOCK TABLE execbound.agent_bindings IN ACCESS EXCLUSIVE MODE")
    op.execute("ALTER TABLE execbound.agent_bindings NO FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security = off")
    if (
        op.get_bind()
        .execute(text("SELECT EXISTS (SELECT 1 FROM execbound.agent_bindings)"))
        .scalar_one()
    ):
        # Who bound an agent, when and why is not reconstructible from anything else.
        raise RuntimeError("Cannot downgrade while agent bindings are retained")
    op.execute("SET LOCAL row_security = on")
    for signature in SIGNATURES:
        op.execute(f"DROP FUNCTION execbound.{signature}")
    op.execute("DROP TABLE execbound.agent_bindings")
    op.execute("GRANT UPDATE (linked_principal_id) ON execbound.monitor_agents TO execbound_app")
