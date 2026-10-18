# SPDX-License-Identifier: AGPL-3.0-only
"""Entra admin consent: a directory an administrator consented to, read with the deployment's app.

`monitor_connections.credential_mode` admits `platform_app`, an Entra connection read with the
deployment's own app registration after a directory administrator consented to it. Such a
connection holds no key, so `key_fingerprint` is null exactly for it and set for every other
connection, and it records who consented and when (`consented_at`, `consented_by`), which no
other connection does.

`monitor_connect_attempts` is the record of every attempt to connect a directory or to update a
connection's consent: who started it, in which space, for which label or connection, the
SHA-256 digests of its OAuth `state`, of the value in the starting browser's binding cookie and
of its OpenID Connect nonce, the directory a verified sign-in named, and how it ended. An attempt
lives ten minutes. The runtime only reads it; four definer functions write it, and no row is
deleted. `admin_start_connect` refuses before anyone leaves for Microsoft wherever the database
can already decide: a full workspace, a space that already has an Entra connection, and more
than five live attempts or twenty in a rolling day per tenant. `admin_record_signin` takes the
directory a verified id_token named and refuses one that any workspace has connected, so no
consent is asked for it. `admin_complete_consent` creates the connection, or records the new
consent on the connection an update names, after checking every rule again. `admin_refuse_connect`
ends a live attempt as refused, with the step that refused it, for a refusal decided outside the
database (a token, a cookie, Microsoft's own error), because the runtime cannot write the row.

One directory is connected once across the whole deployment. `monitor_connections_directory_once`
is a unique index on the lowercased directory of every active Entra connection, which row
security does not limit. Because a definer function under row security sees one tenant, the
sign-in step reads `monitor_directory_claims` instead: one SHA-256 digest per active Entra
connection's directory, with no tenant column, so a claim names no workspace. The runtime holds
no privilege on it at all. `monitor_directory_claim_sync`, a definer trigger, keeps it equal to
the active Entra connections in the statement that changes them.

`monitor_connect_attempts.principal_id` and `monitor_connections.consented_by` are guarded
against the scheduler principal (`GUARDED_ADDED`): the attempt's principal is the authority that
creates a connection at the callback, and a consenter granted a directory read.

The upgrade refuses, naming only a count, while two active Entra connections share a directory,
so an operator decides which stays. The downgrade refuses while any connection is `platform_app`
or any attempt exists, because the schema below this revision cannot express either; otherwise
it drops what this revision added and requires the key fingerprint again.
"""

from alembic import op
from sqlalchemy import text

revision = "0088_monitor_entra_consent"
down_revision = "0087_monitor_sealed_keys"
branch_labels = None
depends_on = None

TENANT = "nullif((SELECT current_setting('execbound.tenant_id', true)), '')::uuid"
SUPABASE_ROLES = ("anon", "authenticated", "service_role")
GRAPH_ORIGIN = "https://graph.microsoft.com"
GUID = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
DIGEST = "^[0-9a-f]{64}$"

# The columns this revision guards against the scheduler principal. The application's copy is
# `execbound.principal_columns.GUARDED`, which equals 0064's copy together with every later
# migration's `GUARDED_ADDED` (tests/test_scheduled_jobs_schema.py).
GUARDED_ADDED = (
    ("monitor_connect_attempts", "principal_id"),
    ("monitor_connections", "consented_by"),
)

ATTEMPTS = rf"""
CREATE TABLE execbound.monitor_connect_attempts (
    tenant_id uuid NOT NULL REFERENCES execbound.tenants(tenant_id),
    attempt_id uuid NOT NULL,
    principal_id uuid NOT NULL,
    space_id uuid NOT NULL,
    -- The connection an update of consent names, and once a new connection's consent is
    -- complete, the connection it created.
    connection_id uuid,
    -- A new connection's label, chosen before the sign-in; an update keeps its connection's.
    label text CHECK (
        length(label) BETWEEN 1 AND 96 AND btrim(label) <> '' AND label !~ '[[:cntrl:]]'
    ),
    state_hash text NOT NULL UNIQUE CHECK (state_hash ~ '{DIGEST}'),
    binding_hash text NOT NULL CHECK (binding_hash ~ '{DIGEST}'),
    nonce_hash text NOT NULL CHECK (nonce_hash ~ '{DIGEST}'),
    state text NOT NULL
        CHECK (state IN ('started', 'signed_in', 'consented', 'refused', 'expired')),
    -- The directory a verified sign-in named, lowercased.
    directory_ref text CHECK (directory_ref ~ '{GUID}'),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    refusal_code text CHECK (refusal_code ~ '^[A-Z_]{{1,48}}$'),
    -- The callback that refused it, so the landing page knows whether Microsoft may already
    -- hold a consent; unknown where nothing reached a callback.
    refused_step text CHECK (refused_step IN ('signed_in', 'consented')),
    PRIMARY KEY (tenant_id, attempt_id),
    FOREIGN KEY (tenant_id, principal_id) REFERENCES execbound.principals(tenant_id, principal_id),
    FOREIGN KEY (tenant_id, space_id) REFERENCES execbound.spaces(tenant_id, space_id),
    FOREIGN KEY (tenant_id, connection_id)
        REFERENCES execbound.monitor_connections(tenant_id, connection_id),
    CONSTRAINT monitor_connect_attempts_lifetime
        CHECK (expires_at = created_at + interval '10 minutes'),
    -- No directory before a sign-in verified one, and always one after a sign-in or consent;
    -- an attempt refused or expired keeps whatever its last step had.
    CONSTRAINT monitor_connect_attempts_directory CHECK (
        (state <> 'started' OR directory_ref IS NULL)
        AND (state NOT IN ('signed_in', 'consented') OR directory_ref IS NOT NULL)
    ),
    CONSTRAINT monitor_connect_attempts_refusal CHECK (
        (state = 'refused') = (refusal_code IS NOT NULL)
        AND (refused_step IS NULL OR state = 'refused')
    ),
    CONSTRAINT monitor_connect_attempts_consumed
        CHECK ((consumed_at IS NULL) = (state IN ('started', 'signed_in'))),
    -- A label for a new connection or a connection to update, and both only once a new
    -- connection's consent has created it.
    CONSTRAINT monitor_connect_attempts_target CHECK (
        (label IS NOT NULL OR connection_id IS NOT NULL)
        AND (state = 'consented' OR label IS NULL OR connection_id IS NULL)
    )
)
"""

CLAIMS = f"""
CREATE TABLE execbound.monitor_directory_claims (
    directory_key text PRIMARY KEY CHECK (directory_key ~ '{DIGEST}'),
    claimed_at timestamptz NOT NULL
)
"""

# A digest names a directory without naming its workspace.
CLAIM_KEY = "encode(sha256(convert_to(lower({}), 'UTF8')), 'hex')"

SYNC = f"""
CREATE FUNCTION execbound.monitor_directory_claim_sync() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    -- The claims are the active Entra connections, of every credential mode. The runtime
    -- inserts and revokes connections with no privilege on the claims, so this runs as their
    -- owner; it is fired, never called.
    IF TG_OP = 'UPDATE' AND OLD.kind = 'entra_agent_id' AND OLD.active
       AND (NOT NEW.active OR NEW.directory_ref IS DISTINCT FROM OLD.directory_ref) THEN
        DELETE FROM execbound.monitor_directory_claims
         WHERE directory_key = {CLAIM_KEY.format("OLD.directory_ref")};
    END IF;
    IF NEW.kind = 'entra_agent_id' AND NEW.active
       AND (TG_OP = 'INSERT' OR NOT OLD.active
            OR NEW.directory_ref IS DISTINCT FROM OLD.directory_ref) THEN
        INSERT INTO execbound.monitor_directory_claims (directory_key, claimed_at)
        VALUES ({CLAIM_KEY.format("NEW.directory_ref")}, now());
    END IF;
    RETURN NULL;
END $$
"""

# An active administrator of an active tenant: 0086's actor check, which never admits an agent
# or a workspace's scheduler principal.
ACTOR = """
    IF v_tenant IS NULL OR NOT EXISTS (
        SELECT 1 FROM execbound.tenants t WHERE t.tenant_id = v_tenant AND t.active
    ) THEN
        RAISE EXCEPTION 'INVALID_TENANT';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM execbound.principals p
         WHERE p.tenant_id = v_tenant AND p.principal_id = v_actor AND p.active
           AND p.kind NOT IN ('AGENT', 'SYSTEM')
           AND execbound.access_effective_kind(v_actor) = 'ADMIN'
    ) THEN
        RAISE EXCEPTION 'INVALID_ACTOR';
    END IF;
"""

# The space exists, is not archived, and the actor administers it: the monitoring store's space
# rule (`_check_connection_space`), where a membership narrows the tenant's administrator and a
# reviewer's seat never grants collector administration.
SPACE = """
    SELECT s.archived_at IS NOT NULL INTO v_archived FROM execbound.spaces s
     WHERE s.tenant_id = v_tenant AND s.space_id = v_space;
    IF v_archived IS NULL THEN
        RAISE EXCEPTION 'INVALID_SPACE';
    END IF;
    IF v_archived THEN
        RAISE EXCEPTION 'SPACE_ARCHIVED';
    END IF;
    IF EXISTS (
        SELECT 1 FROM execbound.space_members m
         WHERE m.tenant_id = v_tenant AND m.principal_id = v_actor
    ) AND NOT EXISTS (
        SELECT 1 FROM execbound.space_members m
         WHERE m.tenant_id = v_tenant AND m.principal_id = v_actor
           AND m.space_id = v_space AND m.role = 'ADMIN'
    ) THEN
        RAISE EXCEPTION 'INVALID_ACTOR';
    END IF;
"""

# The connection registry lock the store and the sealed connections take, so every rule below
# is decided against one count.
LOCK = """
    PERFORM pg_advisory_xact_lock(
        hashtextextended('monitor-connections:' || v_tenant::text, 0));
"""

# What a new connection needs of its workspace and space: the store's capacity (MAX_CONNECTIONS,
# revoked connections counted as the store counts them) and one active Entra connection per
# space, of any credential mode.
NEW_CONNECTION = """
    IF (SELECT count(*) FROM execbound.monitor_connections c
         WHERE c.tenant_id = v_tenant) >= 20 THEN
        RAISE EXCEPTION 'CONNECTION_CAPACITY';
    END IF;
    IF EXISTS (
        SELECT 1 FROM execbound.monitor_connections c
         WHERE c.tenant_id = v_tenant AND c.active AND c.kind = 'entra_agent_id'
           AND c.space_id = v_space
    ) THEN
        RAISE EXCEPTION 'CONNECTION_EXISTS';
    END IF;
"""

# What an update needs of its connection: still this tenant's, active and consented.
UPDATED_CONNECTION = """
    SELECT c.space_id, c.directory_ref INTO v_connection_space, v_connection_directory
      FROM execbound.monitor_connections c
     WHERE c.tenant_id = v_tenant AND c.connection_id = v_connection AND c.active
       AND c.credential_mode = 'platform_app'
       FOR UPDATE;
    IF v_connection_space IS NULL THEN
        RAISE EXCEPTION 'INVALID_STATE';
    END IF;
"""

# A directory some active Entra connection, in any workspace, already holds.
CLAIMED = f"""
    IF EXISTS (
        SELECT 1 FROM execbound.monitor_directory_claims d
         WHERE d.directory_key = {CLAIM_KEY.format("v_directory")}
    ) THEN
        RAISE EXCEPTION 'DIRECTORY_UNAVAILABLE';
    END IF;
"""

# The attempt the callback's `state` names, live, from the browser that started it. Codes, not
# reasons: a caller maps every one of them to one refusal.
FENCED = """
    IF v_tenant IS NULL THEN
        RAISE EXCEPTION 'INVALID_TENANT';
    END IF;
"""

ATTEMPT = """
    IF p_state_hash IS NULL OR p_binding_hash IS NULL THEN
        RAISE EXCEPTION 'INVALID_INPUT';
    END IF;
    SELECT * INTO v_attempt FROM execbound.monitor_connect_attempts a
     WHERE a.tenant_id = v_tenant AND a.attempt_id = p_attempt
       AND a.state_hash = p_state_hash
       FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'INVALID_STATE';
    END IF;
    IF v_attempt.consumed_at IS NOT NULL THEN
        RAISE EXCEPTION 'ATTEMPT_USED';
    END IF;
    IF v_attempt.expires_at <= now() THEN
        RAISE EXCEPTION 'ATTEMPT_EXPIRED';
    END IF;
    IF v_attempt.binding_hash <> p_binding_hash THEN
        RAISE EXCEPTION 'BINDING_MISMATCH';
    END IF;
    v_actor := v_attempt.principal_id;
    v_space := v_attempt.space_id;
    v_connection := v_attempt.connection_id;
"""

START = (
    r"""
CREATE FUNCTION execbound.admin_start_connect(
    p_actor uuid, p_space uuid, p_attempt uuid, p_connection uuid, p_label text,
    p_state_hash text, p_binding_hash text, p_nonce_hash text)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_actor uuid := p_actor;
    v_space uuid := p_space;
    v_connection uuid := p_connection;
    v_archived boolean;
    v_connection_space uuid;
    v_connection_directory text;
BEGIN
"""
    + ACTOR
    + rf"""
    IF p_attempt IS NULL OR p_space IS NULL
       OR p_state_hash IS NULL OR p_state_hash !~ '{DIGEST}'
       OR p_binding_hash IS NULL OR p_binding_hash !~ '{DIGEST}'
       OR p_nonce_hash IS NULL OR p_nonce_hash !~ '{DIGEST}'
       -- A new connection is named by its label; an update by its connection, never both.
       OR (p_connection IS NULL) = (p_label IS NULL)
       OR (p_label IS NOT NULL AND (length(p_label) NOT BETWEEN 1 AND 96
                                    OR btrim(p_label) = '' OR p_label ~ '[[:cntrl:]]')) THEN
        RAISE EXCEPTION 'INVALID_INPUT';
    END IF;
"""
    + LOCK
    + """
    IF v_connection IS NOT NULL THEN
"""
    + UPDATED_CONNECTION
    + """
        -- An update runs in its connection's own space.
        IF v_connection_space <> v_space THEN
            RAISE EXCEPTION 'INVALID_INPUT';
        END IF;
    END IF;
"""
    + SPACE
    + """
    IF v_connection IS NULL THEN
"""
    + NEW_CONNECTION
    + """
    END IF;
    -- Attempts that lapsed unanswered are recorded as expired, so the record says so and they
    -- are no longer live.
    UPDATE execbound.monitor_connect_attempts
       SET state = 'expired', consumed_at = now()
     WHERE tenant_id = v_tenant AND state IN ('started', 'signed_in') AND expires_at <= now();
    -- Five live at once and twenty in any rolling day, whatever became of them: bounded
    -- volume for a record that is never deleted.
    IF (SELECT count(*) FROM execbound.monitor_connect_attempts a
         WHERE a.tenant_id = v_tenant AND a.state IN ('started', 'signed_in')) >= 5
       OR (SELECT count(*) FROM execbound.monitor_connect_attempts a
            WHERE a.tenant_id = v_tenant AND a.created_at > now() - interval '24 hours') >= 20
    THEN
        RAISE EXCEPTION 'ATTEMPT_CAPACITY';
    END IF;
    INSERT INTO execbound.monitor_connect_attempts
        (tenant_id, attempt_id, principal_id, space_id, connection_id, label, state_hash,
         binding_hash, nonce_hash, state, created_at, expires_at)
    VALUES (v_tenant, p_attempt, v_actor, v_space, p_connection, p_label, p_state_hash,
            p_binding_hash, p_nonce_hash, 'started', now(), now() + interval '10 minutes');
END $$
"""
)

SIGNIN = (
    r"""
CREATE FUNCTION execbound.admin_record_signin(
    p_attempt uuid, p_state_hash text, p_binding_hash text, p_nonce_hash text,
    p_directory text)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_attempt execbound.monitor_connect_attempts%ROWTYPE;
    v_actor uuid;
    v_space uuid;
    v_connection uuid;
    v_archived boolean;
    v_connection_space uuid;
    v_connection_directory text;
    v_directory text := lower(p_directory);
BEGIN
"""
    + FENCED
    + rf"""
    IF v_directory IS NULL OR v_directory !~ '{GUID}' THEN
        RAISE EXCEPTION 'INVALID_INPUT';
    END IF;
"""
    + LOCK
    + ATTEMPT
    + """
    IF v_attempt.state <> 'started' THEN
        RAISE EXCEPTION 'OUT_OF_ORDER';
    END IF;
    IF p_nonce_hash IS NULL OR v_attempt.nonce_hash <> p_nonce_hash THEN
        RAISE EXCEPTION 'NONCE_MISMATCH';
    END IF;
"""
    + ACTOR
    + SPACE
    + """
    IF v_connection IS NULL THEN
"""
    + CLAIMED
    + NEW_CONNECTION
    + """
    ELSE
"""
    + UPDATED_CONNECTION
    + """
        -- An update consents for the directory its connection already reads, and no other.
        IF lower(v_connection_directory) <> v_directory THEN
            RAISE EXCEPTION 'DIRECTORY_MISMATCH';
        END IF;
    END IF;
    UPDATE execbound.monitor_connect_attempts
       SET state = 'signed_in', directory_ref = v_directory
     WHERE tenant_id = v_tenant AND attempt_id = p_attempt;
END $$
"""
)

COMPLETE = (
    r"""
CREATE FUNCTION execbound.admin_complete_consent(
    p_attempt uuid, p_state_hash text, p_binding_hash text, p_directory text,
    p_client_ref text)
RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_attempt execbound.monitor_connect_attempts%ROWTYPE;
    v_actor uuid;
    v_space uuid;
    v_connection uuid;
    v_archived boolean;
    v_connection_space uuid;
    v_connection_directory text;
    v_directory text := lower(p_directory);
    v_constraint text;
BEGIN
"""
    + FENCED
    + rf"""
    IF v_directory IS NULL OR v_directory !~ '{GUID}'
       OR p_client_ref IS NULL OR lower(p_client_ref) !~ '{GUID}' THEN
        RAISE EXCEPTION 'INVALID_INPUT';
    END IF;
"""
    + LOCK
    + ATTEMPT
    + """
    IF v_attempt.state <> 'signed_in' THEN
        RAISE EXCEPTION 'OUT_OF_ORDER';
    END IF;
    -- Microsoft's callback names the directory that consented; it is the one the sign-in
    -- verified, or nothing is created.
    IF v_attempt.directory_ref <> v_directory THEN
        RAISE EXCEPTION 'DIRECTORY_MISMATCH';
    END IF;
"""
    + ACTOR
    + SPACE
    + """
    IF v_connection IS NULL THEN
"""
    + CLAIMED
    + NEW_CONNECTION
    + f"""
        v_connection := gen_random_uuid();
        BEGIN
            -- The deployment's app reads the directory; the first collection is asked for by
            -- whoever consented.
            INSERT INTO execbound.monitor_connections
                (tenant_id, connection_id, label, base_url, key_fingerprint, created_at,
                 created_by, kind, directory_ref, client_ref, space_id, credential_mode,
                 consented_at, consented_by, collect_requested_at, collect_requested_by)
            VALUES (v_tenant, v_connection, v_attempt.label, '{GRAPH_ORIGIN}', NULL, now(),
                    v_actor, 'entra_agent_id', v_directory, lower(p_client_ref), v_space,
                    'platform_app', now(), v_actor, now(), v_actor);
        EXCEPTION WHEN unique_violation THEN
            GET STACKED DIAGNOSTICS v_constraint = CONSTRAINT_NAME;
            IF v_constraint = 'monitor_connections_directory_once' THEN
                RAISE EXCEPTION 'DIRECTORY_UNAVAILABLE';
            ELSIF v_constraint = 'monitor_connections_one_active' THEN
                RAISE EXCEPTION 'CONNECTION_EXISTS';
            END IF;
            RAISE;
        END;
    ELSE
"""
    + UPDATED_CONNECTION
    + """
        IF lower(v_connection_directory) <> v_directory THEN
            RAISE EXCEPTION 'DIRECTORY_MISMATCH';
        END IF;
        -- The new consent, and a collection to learn which permissions it holds; a request
        -- already waiting is kept.
        UPDATE execbound.monitor_connections
           SET consented_at = now(), consented_by = v_actor,
               collect_requested_by = CASE WHEN collect_requested_at IS NULL THEN v_actor
                                           ELSE collect_requested_by END,
               collect_requested_at = coalesce(collect_requested_at, now())
         WHERE tenant_id = v_tenant AND connection_id = v_connection;
    END IF;
    UPDATE execbound.monitor_connect_attempts
       SET state = 'consented', consumed_at = now(), connection_id = v_connection
     WHERE tenant_id = v_tenant AND attempt_id = p_attempt;
    RETURN v_connection;
END $$
"""
)

REFUSE = r"""
CREATE FUNCTION execbound.admin_refuse_connect(
    p_attempt uuid, p_state_hash text, p_step text, p_code text)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
BEGIN
    IF v_tenant IS NULL THEN
        RAISE EXCEPTION 'INVALID_TENANT';
    END IF;
    IF p_code IS NULL OR p_code !~ '^[A-Z_]{1,48}$'
       OR (p_step IS NOT NULL AND p_step NOT IN ('signed_in', 'consented')) THEN
        RAISE EXCEPTION 'INVALID_INPUT';
    END IF;
    -- Only a live attempt, and only for whoever holds its `state`: an attempt that ended keeps
    -- how it ended.
    UPDATE execbound.monitor_connect_attempts
       SET state = 'refused', refusal_code = p_code, refused_step = p_step,
           consumed_at = now()
     WHERE tenant_id = v_tenant AND attempt_id = p_attempt AND state_hash = p_state_hash
       AND state IN ('started', 'signed_in');
    RETURN FOUND;
END $$
"""

SIGNATURES = (
    "admin_start_connect(uuid, uuid, uuid, uuid, text, text, text, text)",
    "admin_record_signin(uuid, text, text, text, text)",
    "admin_complete_consent(uuid, text, text, text, text)",
    "admin_refuse_connect(uuid, text, text, text)",
)


def role_exists(role: str) -> bool:
    return bool(
        op.get_bind()
        .execute(text("SELECT 1 FROM pg_roles WHERE rolname = :role"), {"role": role})
        .scalar()
    )


def revoke_platform_roles(statement: str) -> None:
    for role in SUPABASE_ROLES:
        if role_exists(role):
            op.execute(statement.format(role=role))


def upgrade() -> None:
    op.execute(f"""
        ALTER TABLE execbound.monitor_connections
            ADD COLUMN consented_at timestamptz,
            ADD COLUMN consented_by uuid,
            ADD CONSTRAINT monitor_connections_consented_by_fkey
                FOREIGN KEY (tenant_id, consented_by)
                REFERENCES execbound.principals(tenant_id, principal_id),
            ALTER COLUMN key_fingerprint DROP NOT NULL,
            DROP CONSTRAINT monitor_connections_credential_mode_check,
            ADD CONSTRAINT monitor_connections_credential_mode_check
                CHECK (credential_mode IN ('key_file', 'sealed', 'platform_app')),
            ADD CONSTRAINT monitor_connections_platform_kind
                CHECK (credential_mode <> 'platform_app' OR kind = 'entra_agent_id'),
            -- The deployment's own app reads a consented directory, so it alone holds no key.
            ADD CONSTRAINT monitor_connections_platform_keyless
                CHECK ((credential_mode = 'platform_app') = (key_fingerprint IS NULL)),
            ADD CONSTRAINT monitor_connections_consent_pair CHECK (
                (consented_at IS NULL) = (consented_by IS NULL)
                AND (credential_mode = 'platform_app') = (consented_at IS NOT NULL)
            ),
            ADD CONSTRAINT monitor_connections_platform_origin
                CHECK (credential_mode <> 'platform_app' OR base_url = '{GRAPH_ORIGIN}')
    """)
    op.execute(
        "CREATE INDEX monitor_connections_consented_by "
        "ON execbound.monitor_connections (tenant_id, consented_by)"
    )
    op.execute(ATTEMPTS)
    for column in ("principal_id", "space_id", "connection_id"):
        op.execute(
            f"CREATE INDEX monitor_connect_attempts_{column} "
            f"ON execbound.monitor_connect_attempts (tenant_id, {column})"
        )
    op.execute(CLAIMS)

    # One active Entra connection per directory, across tenants. The hosted owner does not
    # bypass row security, so under FORCE the count below would see no tenant and pass, and the
    # backfill would claim nothing; lift it for this section, as 0041 does, and put it back.
    op.execute("LOCK TABLE execbound.monitor_connections IN ACCESS EXCLUSIVE MODE")
    op.execute("ALTER TABLE execbound.monitor_connections NO FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security = off")
    shared = (
        op.get_bind()
        .execute(
            text(
                "SELECT count(*) FROM (SELECT 1 FROM execbound.monitor_connections "
                "WHERE active AND kind = 'entra_agent_id' "
                "GROUP BY lower(directory_ref) HAVING count(*) > 1) d"
            )
        )
        .scalar_one()
    )
    if shared:
        # A count, never a workspace: an operator finds them with their own fenced reads.
        noun = "directory has" if shared == 1 else "directories have"
        raise RuntimeError(
            f"Cannot connect each Microsoft Entra directory once: {shared} {noun} more than "
            "one active Microsoft Entra connection. Revoke all but one connection to each, "
            "then upgrade again."
        )
    op.execute(
        "CREATE UNIQUE INDEX monitor_connections_directory_once "
        "ON execbound.monitor_connections (lower(directory_ref)) "
        "WHERE active AND kind = 'entra_agent_id'"
    )
    op.execute(
        "INSERT INTO execbound.monitor_directory_claims (directory_key, claimed_at) "
        f"SELECT {CLAIM_KEY.format('directory_ref')}, now() "
        "FROM execbound.monitor_connections WHERE active AND kind = 'entra_agent_id'"
    )
    op.execute("SET LOCAL row_security = on")
    op.execute("ALTER TABLE execbound.monitor_connections FORCE ROW LEVEL SECURITY")

    # The claims: forced, with no tenant fence because they name no tenant, read and written
    # only by the role running this migration, which owns the definer functions and trigger
    # below. The runtime holds nothing on them, which `check_runtime` refuses otherwise.
    op.execute("ALTER TABLE execbound.monitor_directory_claims ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE execbound.monitor_directory_claims FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY owner_claims ON execbound.monitor_directory_claims "
        "FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true)"
    )
    op.execute("REVOKE ALL ON execbound.monitor_directory_claims FROM PUBLIC, execbound_app")
    revoke_platform_roles("REVOKE ALL ON execbound.monitor_directory_claims FROM {role}")

    # The attempts: the tenant fence in its initplan form; the runtime reads them and nothing
    # more.
    op.execute("ALTER TABLE execbound.monitor_connect_attempts ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE execbound.monitor_connect_attempts FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY tenant_isolation ON execbound.monitor_connect_attempts "
        f"USING (tenant_id = {TENANT}) WITH CHECK (tenant_id = {TENANT})"
    )
    op.execute("REVOKE ALL ON execbound.monitor_connect_attempts FROM PUBLIC, execbound_app")
    revoke_platform_roles("REVOKE ALL ON execbound.monitor_connect_attempts FROM {role}")
    op.execute("GRANT SELECT ON execbound.monitor_connect_attempts TO execbound_app")

    op.execute(SYNC)
    op.execute("REVOKE ALL ON FUNCTION execbound.monitor_directory_claim_sync() FROM PUBLIC")
    revoke_platform_roles(
        "REVOKE ALL ON FUNCTION execbound.monitor_directory_claim_sync() FROM {role}"
    )
    op.execute(
        "CREATE TRIGGER monitor_directory_claim_sync "
        "AFTER INSERT OR UPDATE OF active, directory_ref ON execbound.monitor_connections "
        "FOR EACH ROW EXECUTE FUNCTION execbound.monitor_directory_claim_sync()"
    )
    # 0064's guard, on this revision's own principal columns.
    for table, column in GUARDED_ADDED:
        op.execute(
            f"CREATE TRIGGER system_guard_{column} BEFORE INSERT OR UPDATE OF {column} "
            f"ON execbound.{table} FOR EACH ROW "
            f"EXECUTE FUNCTION execbound.principal_guard('{column}')"
        )
    for body in (START, SIGNIN, COMPLETE, REFUSE):
        op.execute(body)
    for signature in SIGNATURES:
        op.execute(f"REVOKE ALL ON FUNCTION execbound.{signature} FROM PUBLIC")
        revoke_platform_roles(f"REVOKE ALL ON FUNCTION execbound.{signature} FROM {{role}}")
        op.execute(f"GRANT EXECUTE ON FUNCTION execbound.{signature} TO execbound_app")


def downgrade() -> None:
    op.execute(
        "LOCK TABLE execbound.monitor_connections, execbound.monitor_connect_attempts "
        "IN ACCESS EXCLUSIVE MODE"
    )
    # The hosted owner does not bypass row security, so under FORCE these checks would see no
    # tenant's rows and pass; lift it, as 0087's downgrade does, and put it back below.
    op.execute("ALTER TABLE execbound.monitor_connections NO FORCE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE execbound.monitor_connect_attempts NO FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security = off")
    bind = op.get_bind()
    if bind.execute(
        text(
            "SELECT EXISTS (SELECT 1 FROM execbound.monitor_connections "
            "WHERE credential_mode = 'platform_app')"
        )
    ).scalar_one():
        raise RuntimeError("Cannot downgrade while a consented Microsoft Entra connection exists")
    if bind.execute(
        text("SELECT EXISTS (SELECT 1 FROM execbound.monitor_connect_attempts)")
    ).scalar_one():
        raise RuntimeError("Cannot downgrade while a connection attempt is recorded")
    for signature in SIGNATURES:
        op.execute(f"DROP FUNCTION execbound.{signature}")
    for table, column in GUARDED_ADDED:
        op.execute(f"DROP TRIGGER system_guard_{column} ON execbound.{table}")
    op.execute("DROP TRIGGER monitor_directory_claim_sync ON execbound.monitor_connections")
    op.execute("DROP FUNCTION execbound.monitor_directory_claim_sync()")
    op.execute("DROP TABLE execbound.monitor_connect_attempts")
    op.execute("DROP TABLE execbound.monitor_directory_claims")
    op.execute("DROP INDEX execbound.monitor_connections_directory_once")
    op.execute("DROP INDEX execbound.monitor_connections_consented_by")
    op.execute("""
        ALTER TABLE execbound.monitor_connections
            DROP CONSTRAINT monitor_connections_platform_origin,
            DROP CONSTRAINT monitor_connections_consent_pair,
            DROP CONSTRAINT monitor_connections_platform_keyless,
            DROP CONSTRAINT monitor_connections_platform_kind,
            DROP CONSTRAINT monitor_connections_credential_mode_check,
            ADD CONSTRAINT monitor_connections_credential_mode_check
                CHECK (credential_mode IN ('key_file', 'sealed')),
            ALTER COLUMN key_fingerprint SET NOT NULL,
            DROP CONSTRAINT monitor_connections_consented_by_fkey,
            DROP COLUMN consented_by,
            DROP COLUMN consented_at
    """)
    op.execute("SET LOCAL row_security = on")
    op.execute("ALTER TABLE execbound.monitor_connections FORCE ROW LEVEL SECURITY")
