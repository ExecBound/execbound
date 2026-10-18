"""The assistant's turns: a person's questions and the answers they got, private to them.

`assistant_turns` is written only through the four SECURITY DEFINER functions below; the
runtime role reads it and nothing more. Each function takes the tenant from the fence
setting, verifies the acting person inside the database (an active HUMAN_APPROVER or ADMIN
of an active tenant), and for a turn requires that the actor is the one who asked. A turn
moves RUNNING to COMPLETED or FAILED once; a failure carries one reason from a closed list.
`assistant_turn_retire` nulls the text of turns completed thirty days ago and keeps their
counts. The tenant switch is one column on `tenant_policy_control`, off by default.

Design: docs/superpowers/specs/2026-09-19-assistant-design.md (#330).
"""

from alembic import op
from sqlalchemy import text

revision = "0038_assistant_turns"
down_revision = "0037_agent_bindings"
branch_labels = None
depends_on = None

SIGNATURES = (
    "assistant_turn_create(uuid, uuid, text, uuid, text, text, timestamptz)",
    "assistant_turn_step(uuid, uuid, text)",
    "assistant_turn_complete(uuid, uuid, text, text, jsonb, jsonb, jsonb, integer, integer, "
    "integer, timestamptz)",
    "assistant_turn_retire(uuid, timestamptz)",
)

CONTEXT_KINDS = "('question', 'execution', 'approval', 'finding', 'agent', 'policy_change')"
REASONS = (
    "('TOOL_LIMIT', 'TIME_LIMIT', 'TOKEN_LIMIT', 'REFUSED_SECRET', 'RECOMMENDATION', "
    "'MODEL_ERROR', 'ABANDONED')"
)

# The tenant comes from the fence setting; the actor must be an active person (an approver
# or an administrator) of that active tenant. The assistant reads with a person's authority
# and a person's turns are theirs, so an agent principal can never own one.
PERSON_CHECK = """
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
          AND p.active AND p.kind IN ('HUMAN_APPROVER', 'ADMIN')
    ) THEN
        RAISE EXCEPTION 'INVALID_ACTOR';
    END IF;
"""

ADMIN_CHECK = """
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

# The turn is the actor's own and is locked for the statement that changes it.
OWN_TURN = """
    SELECT state INTO v_state FROM execbound.assistant_turns
    WHERE tenant_id = v_tenant AND turn_id = p_turn AND principal_id = p_actor
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'INVALID_TURN';
    END IF;
    IF v_state <> 'RUNNING' THEN
        RAISE EXCEPTION 'INVALID_STATE';
    END IF;
"""

FUNCTIONS = (
    f"""
CREATE FUNCTION execbound.assistant_turn_create(
    p_actor uuid, p_turn uuid, p_context_kind text, p_context_id uuid, p_question text,
    p_model text, p_now timestamptz)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
BEGIN
    {PERSON_CHECK}
    IF p_turn IS NULL OR p_now IS NULL THEN
        RAISE EXCEPTION 'INVALID_TURN';
    END IF;
    IF p_context_kind IS NULL OR p_context_kind NOT IN {CONTEXT_KINDS}
       OR (p_context_kind = 'question') <> (p_context_id IS NULL) THEN
        RAISE EXCEPTION 'INVALID_CONTEXT';
    END IF;
    IF p_question IS NOT NULL AND char_length(p_question) NOT BETWEEN 1 AND 1000 THEN
        RAISE EXCEPTION 'INVALID_QUESTION';
    END IF;
    IF p_model IS NULL OR char_length(p_model) NOT BETWEEN 1 AND 80 THEN
        RAISE EXCEPTION 'INVALID_MODEL';
    END IF;
    INSERT INTO execbound.assistant_turns (
        tenant_id, turn_id, principal_id, context_kind, context_id, question, state,
        model, created_at)
    VALUES (v_tenant, p_turn, p_actor, p_context_kind, p_context_id, p_question, 'RUNNING',
        p_model, p_now);
END $$
""",
    f"""
CREATE FUNCTION execbound.assistant_turn_step(p_actor uuid, p_turn uuid, p_step text)
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_state text;
    v_count integer;
BEGIN
    {PERSON_CHECK}
    IF p_step IS NULL OR char_length(p_step) NOT BETWEEN 1 AND 200 THEN
        RAISE EXCEPTION 'INVALID_STEP';
    END IF;
    {OWN_TURN}
    UPDATE execbound.assistant_turns SET steps = steps || to_jsonb(p_step)
    WHERE tenant_id = v_tenant AND turn_id = p_turn AND jsonb_array_length(steps) < 16
    RETURNING jsonb_array_length(steps) INTO v_count;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'STEP_LIMIT';
    END IF;
    RETURN v_count;
END $$
""",
    f"""
CREATE FUNCTION execbound.assistant_turn_complete(
    p_actor uuid, p_turn uuid, p_state text, p_reason text, p_answer jsonb, p_cited jsonb,
    p_tools jsonb, p_input integer, p_cached integer, p_output integer, p_now timestamptz)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_state text;
BEGIN
    {PERSON_CHECK}
    IF p_now IS NULL OR p_input IS NULL OR p_cached IS NULL OR p_output IS NULL
       OR p_input < 0 OR p_cached < 0 OR p_output < 0 THEN
        RAISE EXCEPTION 'INVALID_USAGE';
    END IF;
    IF p_state = 'COMPLETED' THEN
        IF p_reason IS NOT NULL OR p_answer IS NULL THEN
            RAISE EXCEPTION 'INVALID_ANSWER';
        END IF;
    ELSIF p_state = 'FAILED' THEN
        IF p_reason IS NULL OR p_reason NOT IN {REASONS} OR p_answer IS NOT NULL THEN
            RAISE EXCEPTION 'INVALID_REASON';
        END IF;
    ELSE
        RAISE EXCEPTION 'INVALID_STATE';
    END IF;
    IF p_cited IS NULL OR jsonb_typeof(p_cited) <> 'array'
       OR p_tools IS NULL OR jsonb_typeof(p_tools) <> 'array' THEN
        RAISE EXCEPTION 'INVALID_ANSWER';
    END IF;
    {OWN_TURN}
    UPDATE execbound.assistant_turns
    SET state = p_state, reason = p_reason, answer = p_answer, cited_ids = p_cited,
        tool_names = p_tools, input_tokens = p_input, cached_tokens = p_cached,
        output_tokens = p_output, completed_at = p_now
    WHERE tenant_id = v_tenant AND turn_id = p_turn;
END $$
""",
    f"""
CREATE FUNCTION execbound.assistant_turn_retire(p_actor uuid, p_now timestamptz)
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_count integer;
BEGIN
    {ADMIN_CHECK}
    IF p_now IS NULL THEN
        RAISE EXCEPTION 'INVALID_TURN';
    END IF;
    UPDATE execbound.assistant_turns
    SET question = NULL, steps = '[]'::jsonb, answer = NULL, cited_ids = '[]'::jsonb,
        retired_at = p_now
    WHERE tenant_id = v_tenant AND retired_at IS NULL AND completed_at IS NOT NULL
      AND completed_at <= p_now - interval '30 days';
    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END $$
""",
)


def _role_exists(role: str) -> bool:
    return bool(
        op.get_bind()
        .execute(text("SELECT 1 FROM pg_roles WHERE rolname = :role"), {"role": role})
        .scalar()
    )


def upgrade() -> None:
    op.execute(f"""
        CREATE TABLE execbound.assistant_turns (
            tenant_id uuid NOT NULL REFERENCES execbound.tenants,
            turn_id uuid NOT NULL,
            principal_id uuid NOT NULL,
            context_kind text NOT NULL CHECK (context_kind IN {CONTEXT_KINDS}),
            context_id uuid,
            question text CHECK (question IS NULL OR char_length(question) BETWEEN 1 AND 1000),
            state text NOT NULL CHECK (state IN ('RUNNING', 'COMPLETED', 'FAILED')),
            reason text CHECK (reason IS NULL OR reason IN {REASONS}),
            steps jsonb NOT NULL DEFAULT '[]'::jsonb,
            answer jsonb,
            cited_ids jsonb NOT NULL DEFAULT '[]'::jsonb,
            model text NOT NULL CHECK (char_length(model) BETWEEN 1 AND 80),
            tool_names jsonb NOT NULL DEFAULT '[]'::jsonb,
            input_tokens integer NOT NULL DEFAULT 0 CHECK (input_tokens >= 0),
            cached_tokens integer NOT NULL DEFAULT 0 CHECK (cached_tokens >= 0),
            output_tokens integer NOT NULL DEFAULT 0 CHECK (output_tokens >= 0),
            created_at timestamptz NOT NULL,
            completed_at timestamptz,
            retired_at timestamptz,
            PRIMARY KEY (tenant_id, turn_id),
            FOREIGN KEY (tenant_id, principal_id)
                REFERENCES execbound.principals (tenant_id, principal_id),
            CHECK ((state = 'RUNNING') = (completed_at IS NULL)),
            CHECK ((state = 'FAILED') = (reason IS NOT NULL)),
            CHECK ((context_kind = 'question') = (context_id IS NULL)),
            CHECK (completed_at IS NULL OR completed_at >= created_at),
            CHECK (retired_at IS NULL OR completed_at IS NOT NULL)
        )
    """)
    op.execute(
        "CREATE INDEX assistant_turns_person ON execbound.assistant_turns "
        "(tenant_id, principal_id, created_at DESC)"
    )
    op.execute(
        "CREATE INDEX assistant_turns_created ON execbound.assistant_turns "
        "(tenant_id, created_at DESC)"
    )
    op.execute("ALTER TABLE execbound.assistant_turns ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE execbound.assistant_turns FORCE ROW LEVEL SECURITY")
    op.execute("""
        CREATE POLICY tenant_isolation ON execbound.assistant_turns
        USING (tenant_id = nullif(
            (SELECT current_setting('execbound.tenant_id', true)), ''
        )::uuid)
        WITH CHECK (tenant_id = nullif(
            (SELECT current_setting('execbound.tenant_id', true)), ''
        )::uuid)
    """)
    op.execute("REVOKE ALL ON execbound.assistant_turns FROM PUBLIC")
    for role in ("anon", "authenticated", "service_role", "execbound_app"):
        if _role_exists(role):
            op.execute(f"REVOKE ALL ON execbound.assistant_turns FROM {role}")
    op.execute("GRANT SELECT ON execbound.assistant_turns TO execbound_app")
    # The tenant switch: off until an ADMIN turns it on with a reason.
    op.execute(
        "ALTER TABLE execbound.tenant_policy_control "
        "ADD COLUMN assistant_enabled boolean NOT NULL DEFAULT false"
    )
    op.execute(
        "GRANT UPDATE (assistant_enabled) ON execbound.tenant_policy_control TO execbound_app"
    )
    for body in FUNCTIONS:
        op.execute(body)
    for signature in SIGNATURES:
        op.execute(f"REVOKE ALL ON FUNCTION execbound.{signature} FROM PUBLIC")
        for role in ("anon", "authenticated", "service_role"):
            if _role_exists(role):
                op.execute(f"REVOKE ALL ON FUNCTION execbound.{signature} FROM {role}")
        op.execute(f"GRANT EXECUTE ON FUNCTION execbound.{signature} TO execbound_app")


def downgrade() -> None:
    for signature in SIGNATURES:
        op.execute(f"DROP FUNCTION execbound.{signature}")
    op.execute("ALTER TABLE execbound.tenant_policy_control DROP COLUMN assistant_enabled")
    op.execute("DROP TABLE execbound.assistant_turns")
