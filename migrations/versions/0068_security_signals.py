# SPDX-License-Identifier: AGPL-3.0-only
"""Security signals: registered sources and the records they attest (#478).

Spec: docs/superpowers/specs/2026-09-25-security-signal-design.md, section 6. Two tables and
one writer. `signal_sources` is authority data written only by owner commands; the runtime
reads it. `security_signals` is written only by `signal_admit`, which authenticates the
producer's token and checks every field against the registration inside the fence, so the
runtime role holds SELECT on both tables and EXECUTE on the function and nothing else (D9).
Its SELECT on `signal_sources` names every column but the two token digests, as 0042's on
`onboarding_invitations` does: `signal_admit` takes a digest, so at the database layer a digest
is the credential, and a runtime that could read one could post as that producer.
A downgrade is refused while any source, record or `signal` failure counter is retained,
as 0063's is: frozen plans cite these rows, and deleting them is not a recovery procedure.
It is refused too while any `operation_mappings` row names `endpoint-isolation.v2`, or any
bundle, of any status, holds content 0067 cannot parse or serve: a `signal_mappings` key, a
mapping naming v2 or naming the action its ref serves, or a context setting, top-level or in
the ruleset, naming v2 or a `signal` source. That is 0009's rule, for 0009's reason: the
older revision's strict models cannot parse or serve that content, including a DRAFT bundle
that was never validated.
`executions`, `execution_events` and `audit_events` are not scanned: a frozen v2 plan cannot
exist without a `security_signals` row, and a v2 audit record cannot exist without an
`operation_mappings` row, and the product deletes neither, so the checks above already
refuse. Retention pruning (#439) must extend this guard to those three tables, as 0009
scans them, before it deletes either.
"""

from alembic import op
from sqlalchemy import text

revision = "0068_security_signals"
down_revision = "0067_step_up_window"
branch_labels = None
depends_on = None

TENANT = "nullif((SELECT current_setting('execbound.tenant_id', true)), '')::uuid"
VERSION = r"^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$"
# A path filter, in 0009's own style (its NON_V1), naming the one version this migration adds.
V2_NAMED = '? (@ == "endpoint-isolation.v2")'
# A context setting 0067 cannot parse (its `ContextSetting` admits only an inventory or
# incident source) or cannot serve (its catalog has no v2).
SIGNAL_SETTING = (
    '? (@.source_kind == "signal" || @.context_contract_version == "endpoint-isolation.v2")'
)
# Bundle content 0067's strict models cannot parse or serve, in 0009's own shape: any
# `signal_mappings` key (0067's `BundleContent` has no such field), a mapping naming v2 or
# carrying an `action` key (0067's `MappingRef` has no such field), or a context setting,
# top-level or in the ruleset, naming v2 or a `signal` source.
UNREADABLE_BUNDLE = (
    "jsonb_exists(content, 'signal_mappings') OR "
    f"jsonb_path_exists(content, '$.mappings[*].context_contract_version {V2_NAMED}') OR "
    "jsonb_path_exists(content, '$.mappings[*].action') OR "
    f"jsonb_path_exists(content, '$.context_settings[*] {SIGNAL_SETTING}') OR "
    f"jsonb_path_exists(content, '$.ruleset.context[*] {SIGNAL_SETTING}')"
)

SOURCES = """
CREATE TABLE execbound.signal_sources (
    tenant_id uuid NOT NULL,
    source_id uuid NOT NULL,
    space_id uuid NOT NULL,
    offered_tenant_wide boolean NOT NULL DEFAULT false,
    label text NOT NULL CHECK (label ~ '^[A-Za-z0-9][A-Za-z0-9 ._:-]{0,95}$'),
    producer_name text NOT NULL CHECK (producer_name ~ '^[a-z][a-z0-9_.-]{0,63}$'),
    producer_version_min text NOT NULL CHECK (producer_version_min ~ '<VERSION>'),
    producer_version_max text NOT NULL CHECK (producer_version_max ~ '<VERSION>'),
    capabilities text[] NOT NULL CHECK (
        cardinality(capabilities) BETWEEN 1 AND 8
        AND capabilities <@ ARRAY['resource_compromise.v1']::text[]),
    subject_kinds text[] NOT NULL CHECK (
        cardinality(subject_kinds) BETWEEN 1 AND 3 AND subject_kinds <@ ARRAY['resource']::text[]),
    principal_ids uuid[] CHECK (
        principal_ids IS NULL OR cardinality(principal_ids) BETWEEN 1 AND 64),
    -- A scope list, which no foreign key can constrain: an agent id per element, and never a
    -- NULL, which `= ANY` would read as unknown rather than as absent.
    CONSTRAINT signal_sources_no_null_principal
        CHECK (array_position(principal_ids, NULL) IS NULL),
    principal_group_id uuid,
    placement text NOT NULL CHECK (placement IN ('out_of_process')),
    input_path text NOT NULL CHECK (input_path IN ('independent', 'agent_forwarded')),
    attests_liveness boolean NOT NULL,
    registration_version integer NOT NULL DEFAULT 1 CHECK (registration_version >= 1),
    token_hash text NOT NULL CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    previous_token_hash text CHECK (previous_token_hash ~ '^[0-9a-f]{64}$'),
    previous_valid_until timestamptz,
    created_at timestamptz NOT NULL,
    created_by uuid NOT NULL,
    expires_at timestamptz NOT NULL,
    rotated_at timestamptz,
    rotated_by uuid,
    active boolean NOT NULL DEFAULT true,
    revoked_at timestamptz,
    revoked_by uuid,
    rate_window_at timestamptz NOT NULL,
    rate_count integer NOT NULL DEFAULT 0 CHECK (rate_count BETWEEN 0 AND 1000000),
    record_count integer NOT NULL DEFAULT 0 CHECK (record_count BETWEEN 0 AND 500000),
    last_accepted_at timestamptz,
    last_refused_at timestamptz,
    last_refusal_code text CHECK (last_refusal_code IN (
        'SOURCE_RATE_LIMIT', 'CONFLICTING_DUPLICATE', 'CAPABILITY_REFUSED', 'SUBJECT_REFUSED',
        'INCOMPATIBLE_PRODUCER', 'FUTURE_OBSERVATION', 'STALE_ON_ARRIVAL', 'INVALID_SIGNAL',
        'INVALID_SUBJECT', 'SOURCE_CAPACITY')),
    conflict_count integer NOT NULL DEFAULT 0 CHECK (conflict_count >= 0),
    rate_refusal_count integer NOT NULL DEFAULT 0 CHECK (rate_refusal_count >= 0),
    PRIMARY KEY (tenant_id, source_id),
    UNIQUE (token_hash),
    FOREIGN KEY (tenant_id, space_id) REFERENCES execbound.spaces (tenant_id, space_id),
    FOREIGN KEY (tenant_id, created_by) REFERENCES execbound.principals (tenant_id, principal_id),
    FOREIGN KEY (tenant_id, rotated_by) REFERENCES execbound.principals (tenant_id, principal_id),
    FOREIGN KEY (tenant_id, revoked_by) REFERENCES execbound.principals (tenant_id, principal_id),
    FOREIGN KEY (tenant_id, principal_group_id)
        REFERENCES execbound.principal_groups (tenant_id, group_id),
    -- Named, so a refusal says which rule it broke.
    CONSTRAINT signal_sources_one_scope
        CHECK ((principal_ids IS NULL) <> (principal_group_id IS NULL)),
    CONSTRAINT signal_sources_lifetime CHECK (expires_at > created_at),
    CONSTRAINT signal_sources_previous_together
        CHECK ((previous_token_hash IS NULL) = (previous_valid_until IS NULL)),
    CONSTRAINT signal_sources_previous_distinct
        CHECK (previous_token_hash IS NULL OR previous_token_hash <> token_hash),
    CONSTRAINT signal_sources_rotation_together CHECK ((rotated_at IS NULL) = (rotated_by IS NULL)),
    CONSTRAINT signal_sources_revocation_together
        CHECK ((revoked_at IS NULL) = (revoked_by IS NULL)),
    CONSTRAINT signal_sources_revoked_inactive CHECK (revoked_at IS NULL OR NOT active),
    CONSTRAINT signal_sources_version_order
        CHECK (string_to_array(producer_version_min, '.')::integer[]
               <= string_to_array(producer_version_max, '.')::integer[])
)
""".replace("<VERSION>", VERSION)

RECORDS = """
CREATE TABLE execbound.security_signals (
    tenant_id uuid NOT NULL,
    source_id uuid NOT NULL,
    source_event_id text NOT NULL CHECK (source_event_id ~ '^[A-Za-z0-9._:-]{1,128}$'),
    record_digest text NOT NULL CHECK (record_digest ~ '^[0-9a-f]{64}$'),
    registration_version integer NOT NULL CHECK (registration_version >= 1),
    producer_name text NOT NULL,
    producer_version text NOT NULL CHECK (producer_version ~ '<VERSION>'),
    capability text NOT NULL,
    -- `resolution.models.Verdict`'s pattern exactly: no leading or trailing space, so no row
    -- the model would refuse is ever stored.
    verdict text NOT NULL
        CHECK (verdict ~ '^[A-Za-z0-9_.:-]([A-Za-z0-9 _.:-]{0,62}[A-Za-z0-9_.:-])?$'),
    confidence integer NOT NULL CHECK (confidence BETWEEN 0 AND 1000),
    severity text CHECK (severity ~ '^[A-Za-z0-9 _.:-]{1,32}$'),
    subject_kind text NOT NULL CHECK (subject_kind IN ('resource')),
    subject_account_id uuid NOT NULL,
    subject_provider text NOT NULL,
    subject_resource_type text NOT NULL CHECK (subject_resource_type ~ '^[a-z][a-z0-9_]{0,63}$'),
    subject_provider_id text NOT NULL CHECK (length(subject_provider_id) BETWEEN 1 AND 128),
    action text CHECK (action ~ '^[a-z][a-z0-9_.-]{0,79}$'),
    request_reference text CHECK (length(request_reference) BETWEEN 1 AND 200),
    observed_at timestamptz NOT NULL,
    received_at timestamptz NOT NULL,
    expires_at timestamptz,
    attributes jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(attributes) = 'object'),
    evidence_ref text CHECK (length(evidence_ref) BETWEEN 1 AND 256),
    evidence_digest text CHECK (evidence_digest ~ '^[0-9a-f]{64}$'),
    PRIMARY KEY (tenant_id, source_id, source_event_id),
    FOREIGN KEY (tenant_id, source_id) REFERENCES execbound.signal_sources (tenant_id, source_id),
    FOREIGN KEY (tenant_id, subject_account_id, subject_provider)
        REFERENCES execbound.connector_accounts (tenant_id, account_id, provider),
    CONSTRAINT security_signals_expiry_order
        CHECK (expires_at IS NULL OR expires_at > observed_at)
)
""".replace("<VERSION>", VERSION)

ADMIT = """
CREATE FUNCTION execbound.signal_admit(
    p_source uuid, p_token_hash text, p_now timestamptz, p_event_id text,
    p_record_digest text, p_producer_name text, p_producer_version text, p_capability text,
    p_verdict text, p_confidence integer, p_severity text, p_subject_kind text,
    p_subject_account uuid, p_subject_provider text, p_subject_resource_type text,
    p_subject_provider_id text, p_action text, p_request_reference text,
    p_observed_at timestamptz, p_expires_at timestamptz, p_attributes jsonb,
    p_evidence_ref text, p_evidence_digest text)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_source execbound.signal_sources%ROWTYPE;
    v_prior execbound.security_signals%ROWTYPE;
    v_window timestamptz;
    v_count integer;
    v_refusal text;
    v_version integer[];
    v_pass integer;
BEGIN
    IF p_now IS NULL OR abs(extract(epoch FROM (p_now - now()))) > 300 THEN
        RAISE EXCEPTION 'INVALID_CLOCK';
    END IF;
    IF v_tenant IS NULL OR p_source IS NULL OR p_token_hash IS NULL
       OR p_token_hash !~ '^[0-9a-f]{64}$' THEN
        RETURN jsonb_build_object('refused', 'INVALID_SOURCE', 'reason', 'UNKNOWN');
    END IF;
    -- Authenticated before the row is locked: the first pass reads it without a lock, so a
    -- caller who knows a source id but not its token is refused without ever making a genuine
    -- admission wait. The second pass locks the row and checks the token again, because a
    -- rotation may have committed between the two reads, and the state below is read from the
    -- locked row.
    FOR v_pass IN 1..2 LOOP
        IF v_pass = 1 THEN
            SELECT * INTO v_source FROM execbound.signal_sources s
             WHERE s.tenant_id = v_tenant AND s.source_id = p_source;
        ELSE
            SELECT * INTO v_source FROM execbound.signal_sources s
             WHERE s.tenant_id = v_tenant AND s.source_id = p_source FOR UPDATE;
        END IF;
        IF NOT FOUND THEN
            RETURN jsonb_build_object('refused', 'INVALID_SOURCE', 'reason', 'UNKNOWN');
        END IF;
        -- SHA-256 digests of 256-bit random tokens: a timing difference can only reveal digest
        -- bytes, and the token cannot be recovered from its digest (plan decision 9). Written
        -- NULL-safe on purpose: a source never rotated has no previous digest, and
        -- `NOT (false OR NULL)` is NULL, which an IF reads as false and would admit anyone.
        IF v_source.token_hash IS DISTINCT FROM p_token_hash
           AND NOT coalesce(v_source.previous_token_hash = p_token_hash
                            AND p_now < v_source.previous_valid_until, false) THEN
            RETURN jsonb_build_object('refused', 'INVALID_SOURCE', 'reason', 'MISMATCH');
        END IF;
    END LOOP;
    IF NOT v_source.active OR v_source.revoked_at IS NOT NULL THEN
        RETURN jsonb_build_object('refused', 'INVALID_SOURCE', 'reason', 'REVOKED');
    END IF;
    IF NOT (v_source.created_at <= p_now AND p_now < v_source.expires_at) THEN
        RETURN jsonb_build_object('refused', 'INVALID_SOURCE', 'reason', 'EXPIRED');
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM execbound.tenants t WHERE t.tenant_id = v_tenant AND t.active) THEN
        RETURN jsonb_build_object('refused', 'INVALID_SOURCE', 'reason', 'INACTIVE');
    END IF;
    -- The caller is the source from here on. Every refusal below is recorded against its
    -- health and commits, because this function returns rather than raising.
    v_window := v_source.rate_window_at;
    v_count := v_source.rate_count;
    IF p_now >= v_window + interval '1 minute' THEN
        v_window := p_now;
        v_count := 0;
    END IF;
    IF v_count >= 600 THEN
        UPDATE execbound.signal_sources
           SET rate_window_at = v_window, rate_count = v_count,
               rate_refusal_count = rate_refusal_count + 1,
               last_refused_at = p_now, last_refusal_code = 'SOURCE_RATE_LIMIT'
         WHERE tenant_id = v_tenant AND source_id = p_source;
        RETURN jsonb_build_object('refused', 'SOURCE_RATE_LIMIT');
    END IF;
    UPDATE execbound.signal_sources SET rate_window_at = v_window, rate_count = v_count + 1
     WHERE tenant_id = v_tenant AND source_id = p_source;
    -- The identity of the record itself, checked before the duplicate lookup, so a malformed
    -- digest on an event id already accepted is refused as malformed, never as a conflicting
    -- duplicate that the conflict count would record against the source.
    IF p_event_id IS NULL OR p_event_id !~ '^[A-Za-z0-9._:-]{1,128}$'
       OR p_record_digest IS NULL OR p_record_digest !~ '^[0-9a-f]{64}$' THEN
        UPDATE execbound.signal_sources
           SET last_refused_at = p_now, last_refusal_code = 'INVALID_SIGNAL'
         WHERE tenant_id = v_tenant AND source_id = p_source;
        RETURN jsonb_build_object('refused', 'INVALID_SIGNAL');
    END IF;
    -- A retry of an accepted envelope answers its original receipt whatever the time now,
    -- so the duplicate check comes before every freshness check (D10).
    SELECT * INTO v_prior FROM execbound.security_signals g
     WHERE g.tenant_id = v_tenant AND g.source_id = p_source
       AND g.source_event_id = p_event_id;
    IF FOUND THEN
        IF v_prior.record_digest = p_record_digest THEN
            RETURN jsonb_build_object('accepted', true, 'duplicate', true,
                'received_at', v_prior.received_at,
                'registration_version', v_prior.registration_version);
        END IF;
        UPDATE execbound.signal_sources
           SET conflict_count = conflict_count + 1,
               last_refused_at = p_now, last_refusal_code = 'CONFLICTING_DUPLICATE'
         WHERE tenant_id = v_tenant AND source_id = p_source;
        RETURN jsonb_build_object('refused', 'CONFLICTING_DUPLICATE');
    END IF;
    -- Every field against the registration (D5), one condition at a time: an ELSIF chain
    -- evaluates each test on its own, so a malformed version string is never cast.
    IF p_capability IS NULL OR NOT (p_capability = ANY (v_source.capabilities)) THEN
        v_refusal := 'CAPABILITY_REFUSED';
    ELSIF p_subject_kind IS NULL OR NOT (p_subject_kind = ANY (v_source.subject_kinds)) THEN
        v_refusal := 'SUBJECT_REFUSED';
    ELSIF p_producer_name IS DISTINCT FROM v_source.producer_name
          OR p_producer_version IS NULL OR p_producer_version !~ '<VERSION>' THEN
        v_refusal := 'INCOMPATIBLE_PRODUCER';
    ELSIF p_observed_at IS NULL OR p_observed_at > p_now + interval '60 seconds' THEN
        v_refusal := 'FUTURE_OBSERVATION';
    ELSIF p_observed_at <= p_now - interval '3600 seconds' THEN
        v_refusal := 'STALE_ON_ARRIVAL';
    ELSIF p_expires_at IS NOT NULL AND p_expires_at <= p_observed_at THEN
        v_refusal := 'INVALID_SIGNAL';
    ELSIF NOT EXISTS (
        SELECT 1 FROM execbound.connector_accounts a
         WHERE a.tenant_id = v_tenant AND a.account_id = p_subject_account
           AND a.provider = p_subject_provider) THEN
        v_refusal := 'INVALID_SUBJECT';
    ELSIF v_source.record_count >= 500000 THEN
        v_refusal := 'SOURCE_CAPACITY';
    END IF;
    IF v_refusal IS NULL THEN
        v_version := string_to_array(p_producer_version, '.')::integer[];
        IF v_version < string_to_array(v_source.producer_version_min, '.')::integer[]
           OR v_version > string_to_array(v_source.producer_version_max, '.')::integer[] THEN
            v_refusal := 'INCOMPATIBLE_PRODUCER';
        END IF;
    END IF;
    IF v_refusal IS NOT NULL THEN
        UPDATE execbound.signal_sources
           SET last_refused_at = p_now, last_refusal_code = v_refusal
         WHERE tenant_id = v_tenant AND source_id = p_source;
        RETURN jsonb_build_object('refused', v_refusal);
    END IF;
    -- A field the table itself refuses (a verdict with a trailing space, a confidence past
    -- 1000, attributes that are not an object, an empty provider id) is a recorded refusal too:
    -- the block's subtransaction undoes only the insert, so the rate count above commits.
    BEGIN
        INSERT INTO execbound.security_signals (
            tenant_id, source_id, source_event_id, record_digest, registration_version,
            producer_name, producer_version, capability, verdict, confidence, severity,
            subject_kind, subject_account_id, subject_provider, subject_resource_type,
            subject_provider_id, action, request_reference, observed_at, received_at,
            expires_at, attributes, evidence_ref, evidence_digest)
        VALUES (
            v_tenant, p_source, p_event_id, p_record_digest, v_source.registration_version,
            p_producer_name, p_producer_version, p_capability, p_verdict, p_confidence,
            p_severity, p_subject_kind, p_subject_account, p_subject_provider,
            p_subject_resource_type, p_subject_provider_id, p_action, p_request_reference,
            p_observed_at, p_now, p_expires_at, coalesce(p_attributes, '{}'::jsonb),
            p_evidence_ref, p_evidence_digest);
    EXCEPTION WHEN check_violation OR not_null_violation THEN
        UPDATE execbound.signal_sources
           SET last_refused_at = p_now, last_refusal_code = 'INVALID_SIGNAL'
         WHERE tenant_id = v_tenant AND source_id = p_source;
        RETURN jsonb_build_object('refused', 'INVALID_SIGNAL');
    END;
    UPDATE execbound.signal_sources
       SET record_count = record_count + 1, last_accepted_at = p_now
     WHERE tenant_id = v_tenant AND source_id = p_source;
    RETURN jsonb_build_object('accepted', true, 'duplicate', false, 'received_at', p_now,
        'registration_version', v_source.registration_version);
END $$
""".replace("<VERSION>", VERSION)

SIGNATURE = (
    "signal_admit(uuid, text, timestamptz, text, text, text, text, text, text, integer, text, "
    "text, uuid, text, text, text, text, text, timestamptz, timestamptz, jsonb, text, text)"
)
TABLES = ("signal_sources", "security_signals")
# Every column of `signal_sources` but `token_hash` and `previous_token_hash`, named one by one
# rather than taken from the catalog, so a column added later is not granted by accident.
READABLE = (
    "tenant_id",
    "source_id",
    "space_id",
    "offered_tenant_wide",
    "label",
    "producer_name",
    "producer_version_min",
    "producer_version_max",
    "capabilities",
    "subject_kinds",
    "principal_ids",
    "principal_group_id",
    "placement",
    "input_path",
    "attests_liveness",
    "registration_version",
    "previous_valid_until",
    "created_at",
    "created_by",
    "expires_at",
    "rotated_at",
    "rotated_by",
    "active",
    "revoked_at",
    "revoked_by",
    "rate_window_at",
    "rate_count",
    "record_count",
    "last_accepted_at",
    "last_refused_at",
    "last_refusal_code",
    "conflict_count",
    "rate_refusal_count",
)


def role_exists(role: str) -> bool:
    return bool(
        op.get_bind()
        .execute(text("SELECT 1 FROM pg_roles WHERE rolname = :role"), {"role": role})
        .scalar()
    )


def upgrade() -> None:
    op.execute(SOURCES)
    op.execute(RECORDS)
    # Spaces convention (0041): an index leading (tenant_id, space_id).
    op.execute(
        "CREATE INDEX signal_sources_space ON execbound.signal_sources (tenant_id, space_id)"
    )
    # Every foreign key has a covering, non-partial index (`test_database`'s rule).
    op.execute(
        "CREATE INDEX signal_sources_group ON execbound.signal_sources "
        "(tenant_id, principal_group_id)"
    )
    for column, index in (
        ("created_by", "signal_sources_creator"),
        ("rotated_by", "signal_sources_rotated_by"),
        ("revoked_by", "signal_sources_revoked_by"),
    ):
        op.execute(f"CREATE INDEX {index} ON execbound.signal_sources (tenant_id, {column})")
    # Resolution's read: one subject, one capability, the newest record per source.
    op.execute(
        "CREATE INDEX security_signals_subject ON execbound.security_signals "
        "(tenant_id, subject_account_id, subject_provider, subject_resource_type, "
        "subject_provider_id, capability, source_id, observed_at DESC)"
    )
    for table in TABLES:
        op.execute(f"ALTER TABLE execbound.{table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE execbound.{table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON execbound.{table} "
            f"USING (tenant_id = {TENANT}) WITH CHECK (tenant_id = {TENANT})"
        )
        op.execute(f"REVOKE ALL ON execbound.{table} FROM PUBLIC, execbound_app")
        for role in ("anon", "authenticated", "service_role"):
            if role_exists(role):
                op.execute(f"REVOKE ALL ON execbound.{table} FROM {role}")
    op.execute(f"GRANT SELECT ({', '.join(READABLE)}) ON execbound.signal_sources TO execbound_app")
    op.execute("GRANT SELECT ON execbound.security_signals TO execbound_app")
    op.execute(ADMIT)
    op.execute(f"REVOKE ALL ON FUNCTION execbound.{SIGNATURE} FROM PUBLIC")
    for role in ("anon", "authenticated", "service_role"):
        if role_exists(role):
            op.execute(f"REVOKE ALL ON FUNCTION execbound.{SIGNATURE} FROM {role}")
    op.execute(f"GRANT EXECUTE ON FUNCTION execbound.{SIGNATURE} TO execbound_app")
    # Widen the authentication-failure surface catalog (0063) to admit a producer token.
    op.execute(
        "ALTER TABLE execbound.authentication_failures "
        "DROP CONSTRAINT authentication_failures_surface_check"
    )
    op.execute(
        "ALTER TABLE execbound.authentication_failures ADD CONSTRAINT "
        "authentication_failures_surface_check "
        "CHECK (surface IN ('http', 'mcp', 'human', 'monitor', 'token', 'signal'))"
    )


RETENTION_TABLES = (
    *TABLES,
    "authentication_failures",
    "operation_mappings",
    "policy_bundle_contents",
)


def downgrade() -> None:
    # The same shape as 0063: FORCE lifted around each count and restored before anything
    # else, and a refusal while anything a plan or a counter could cite is retained. The
    # last two tables are not this migration's own, exactly as 0009 lifts FORCE on
    # `operation_mappings` and `policy_bundle_contents` (among others) to scan them for
    # content the older revision cannot parse or serve.
    for table in RETENTION_TABLES:
        op.execute(f"ALTER TABLE execbound.{table} NO FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security = off")
    retained = any(
        op.get_bind().execute(text(query)).scalar_one()
        for query in (
            "SELECT EXISTS (SELECT 1 FROM execbound.signal_sources)",
            "SELECT EXISTS (SELECT 1 FROM execbound.security_signals)",
            "SELECT EXISTS (SELECT 1 FROM execbound.authentication_failures "
            "WHERE surface = 'signal')",
            "SELECT EXISTS (SELECT 1 FROM execbound.operation_mappings "
            "WHERE context_contract_version = 'endpoint-isolation.v2')",
            "SELECT EXISTS (SELECT 1 FROM execbound.policy_bundle_contents "
            f"WHERE {UNREADABLE_BUNDLE})",
        )
    )
    for table in RETENTION_TABLES:
        op.execute(f"ALTER TABLE execbound.{table} FORCE ROW LEVEL SECURITY")
    if retained:
        raise RuntimeError(
            "Security signals require a verified full restore; lossy downgrade refused"
        )
    op.execute(f"DROP FUNCTION execbound.{SIGNATURE}")
    op.execute("DROP TABLE execbound.security_signals")
    op.execute("DROP TABLE execbound.signal_sources")
    op.execute(
        "ALTER TABLE execbound.authentication_failures "
        "DROP CONSTRAINT authentication_failures_surface_check"
    )
    op.execute(
        "ALTER TABLE execbound.authentication_failures ADD CONSTRAINT "
        "authentication_failures_surface_check "
        "CHECK (surface IN ('http', 'mcp', 'human', 'monitor', 'token'))"
    )
