# SPDX-License-Identifier: AGPL-3.0-only
"""Sealed collection keys: a Tines key pasted once and sealed to the collector's own key.

`monitor_connections.credential_mode` admits `sealed`, a Tines connection whose API key is kept
as ciphertext that only the collector's private key opens:

- `sealed_ct`, a libsodium sealed box (X25519 with XSalsa20-Poly1305) of a canonical envelope
  that binds the key to its tenant, connection and kind, so a ciphertext copied to another row
  opens and is refused rather than used;
- `sealed_key_id`, which collector key sealed it: `ck1-` and the first sixteen hex digits of the
  SHA-256 of the collector's public key.

A sealed connection holds both and every other connection neither, and only a Tines connection
is sealed. `key_fingerprint` stays on every connection: the SHA-256 of the key, which the
collector compares with the key it opens.

Three definer functions are the only writers of the two columns. `admin_create_sealed_connection`
creates one for an active administrator of an active space they administer, under the
connection registry lock and the store's capacity and one-per-platform-per-space rules, with
the kind's default intervals and a collection request. `admin_replace_sealed_key` replaces an
active sealed connection's key and asks for a collection. `collector_reseal` re-seals one row to
a new collector key, only while the row still holds the collector key and the ciphertext the
re-seal read, so a key an administrator replaced in between is never overwritten with the one
it replaced, and leaves the fingerprint alone because the key is the same. The runtime inserts
and updates neither column (`check_runtime`'s catalogs are unchanged).

The downgrade refuses while any connection is sealed, because the schema below this revision
has no column for its key; otherwise it drops the functions, the checks and the columns and
restores the previous mode check.
"""

from alembic import op
from sqlalchemy import text

revision = "0087_monitor_sealed_keys"
down_revision = "0086_monitor_collect_schedule"
branch_labels = None
depends_on = None

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
         WHERE p.tenant_id = v_tenant AND p.principal_id = p_actor AND p.active
           AND p.kind NOT IN ('AGENT', 'SYSTEM')
           AND execbound.access_effective_kind(p_actor) = 'ADMIN'
    ) THEN
        RAISE EXCEPTION 'INVALID_ACTOR';
    END IF;
"""

# The monitoring store's space rule (`_check_connection_space`): a membership narrows the
# tenant's administrator, and a reviewer's seat never grants collector administration.
ADMINISTERS = """
    IF EXISTS (
        SELECT 1 FROM execbound.space_members m
         WHERE m.tenant_id = v_tenant AND m.principal_id = p_actor
    ) AND NOT EXISTS (
        SELECT 1 FROM execbound.space_members m
         WHERE m.tenant_id = v_tenant AND m.principal_id = p_actor
           AND m.space_id = v_space AND m.role = 'ADMIN'
    ) THEN
        RAISE EXCEPTION 'INVALID_ACTOR';
    END IF;
"""

# A key a collector can hold: its fingerprint, a sealed box's ciphertext and the collector key
# it was sealed to.
SEALED_KEY = r"""
    IF p_fingerprint IS NULL OR p_fingerprint !~ '^[0-9a-f]{64}$'
       OR p_sealed_ct IS NULL OR octet_length(p_sealed_ct) NOT BETWEEN 48 AND 8192
       OR p_key_id IS NULL OR p_key_id !~ '^ck1-[0-9a-f]{16}$' THEN
        RAISE EXCEPTION 'INVALID_INPUT';
    END IF;
"""

CREATE = (
    r"""
CREATE FUNCTION execbound.admin_create_sealed_connection(
    p_actor uuid, p_space uuid, p_connection uuid, p_label text, p_base_url text, p_team text,
    p_fingerprint text, p_sealed_ct bytea, p_key_id text)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_space uuid := p_space;
    v_archived boolean;
BEGIN
"""
    + ACTOR
    + SEALED_KEY
    + r"""
    -- The shapes `_connection_shape` admits for Tines, refused here before anything is
    -- written rather than left to the column checks.
    IF p_connection IS NULL OR p_label IS NULL OR length(p_label) NOT BETWEEN 1 AND 96
       OR btrim(p_label) = '' OR p_label ~ '[[:cntrl:]]'
       OR p_base_url IS NULL
       OR p_base_url !~ '^https://[A-Za-z0-9.-]{1,240}\.tines\.(com|io)$'
       OR (p_team IS NOT NULL AND p_team !~ '^[A-Za-z0-9._:-]{1,64}$') THEN
        RAISE EXCEPTION 'INVALID_INPUT';
    END IF;
    -- The connection registry lock `create_connection` takes, so a sealed connection and an
    -- operator's are counted against one capacity and one rule per space.
    PERFORM pg_advisory_xact_lock(
        hashtextextended('monitor-connections:' || v_tenant::text, 0));
    SELECT s.archived_at IS NOT NULL INTO v_archived FROM execbound.spaces s
     WHERE s.tenant_id = v_tenant AND s.space_id = v_space;
    IF v_archived IS NULL THEN
        RAISE EXCEPTION 'INVALID_SPACE';
    END IF;
    IF v_archived THEN
        RAISE EXCEPTION 'SPACE_ARCHIVED';
    END IF;
"""
    + ADMINISTERS
    + r"""
    -- The store's MAX_CONNECTIONS, revoked connections counted as the store counts them.
    IF (SELECT count(*) FROM execbound.monitor_connections c
         WHERE c.tenant_id = v_tenant) >= 20 THEN
        RAISE EXCEPTION 'CONNECTION_CAPACITY';
    END IF;
    IF EXISTS (
        SELECT 1 FROM execbound.monitor_connections c
         WHERE c.tenant_id = v_tenant AND c.active AND c.kind = 'tines'
           AND c.space_id = v_space
    ) THEN
        RAISE EXCEPTION 'CONNECTION_EXISTS';
    END IF;
    -- The kind's default intervals, and the first collection asked for by whoever connected it.
    INSERT INTO execbound.monitor_connections
        (tenant_id, connection_id, label, base_url, team_id, key_fingerprint, created_at,
         created_by, kind, space_id, credential_mode, sealed_ct, sealed_key_id,
         collect_requested_at, collect_requested_by)
    VALUES (v_tenant, p_connection, p_label, p_base_url, p_team, p_fingerprint, now(),
            p_actor, 'tines', v_space, 'sealed', p_sealed_ct, p_key_id, now(), p_actor);
END $$
"""
)

REPLACE = (
    r"""
CREATE FUNCTION execbound.admin_replace_sealed_key(
    p_actor uuid, p_connection uuid, p_fingerprint text, p_sealed_ct bytea, p_key_id text)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_mode text;
    v_space uuid;
BEGIN
"""
    + ACTOR
    + SEALED_KEY
    + r"""
    SELECT c.credential_mode, c.space_id INTO v_mode, v_space
      FROM execbound.monitor_connections c
     WHERE c.tenant_id = v_tenant AND c.connection_id = p_connection AND c.active
       FOR UPDATE;
    -- Only an active sealed connection takes a pasted key: an operator's key file is
    -- replaced on the host that holds it.
    IF v_mode IS DISTINCT FROM 'sealed' THEN
        RAISE EXCEPTION 'INVALID_STATE';
    END IF;
"""
    + ADMINISTERS
    + r"""
    -- A request already waiting is kept; otherwise the new key is collected with next.
    UPDATE execbound.monitor_connections
       SET sealed_ct = p_sealed_ct, sealed_key_id = p_key_id, key_fingerprint = p_fingerprint,
           collect_requested_by = CASE WHEN collect_requested_at IS NULL THEN p_actor
                                       ELSE collect_requested_by END,
           collect_requested_at = coalesce(collect_requested_at, now())
     WHERE tenant_id = v_tenant AND connection_id = p_connection;
END $$
"""
)

RESEAL = r"""
CREATE FUNCTION execbound.collector_reseal(
    p_connection uuid, p_old_key_id text, p_old_ct bytea, p_sealed_ct bytea, p_key_id text)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
BEGIN
    IF v_tenant IS NULL THEN
        RAISE EXCEPTION 'INVALID_TENANT';
    END IF;
    IF p_sealed_ct IS NULL OR octet_length(p_sealed_ct) NOT BETWEEN 48 AND 8192
       OR p_key_id IS NULL OR p_key_id !~ '^ck1-[0-9a-f]{16}$' THEN
        RAISE EXCEPTION 'INVALID_INPUT';
    END IF;
    -- The same key under a new collector key: the fingerprint is unchanged because the key
    -- is, and a revoked connection is re-sealed too, so the old collector key can be retired.
    -- Only from the ciphertext the re-seal opened: a key replaced since then, perhaps by a
    -- gateway still sealing to the old collector key, is kept, and the next re-seal moves it.
    UPDATE execbound.monitor_connections
       SET sealed_ct = p_sealed_ct, sealed_key_id = p_key_id
     WHERE tenant_id = v_tenant AND connection_id = p_connection
       AND credential_mode = 'sealed' AND sealed_key_id = p_old_key_id
       AND sealed_ct = p_old_ct;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'INVALID_STATE';
    END IF;
END $$
"""

SIGNATURES = (
    "admin_create_sealed_connection(uuid, uuid, uuid, text, text, text, text, bytea, text)",
    "admin_replace_sealed_key(uuid, uuid, text, bytea, text)",
    "collector_reseal(uuid, text, bytea, bytea, text)",
)


def role_exists(role: str) -> bool:
    return bool(
        op.get_bind()
        .execute(text("SELECT 1 FROM pg_roles WHERE rolname = :role"), {"role": role})
        .scalar()
    )


def upgrade() -> None:
    op.execute("""
        ALTER TABLE execbound.monitor_connections
            ADD COLUMN sealed_ct bytea,
            ADD COLUMN sealed_key_id text,
            ADD CONSTRAINT monitor_connections_sealed_ct_check
                CHECK (octet_length(sealed_ct) BETWEEN 48 AND 8192),
            ADD CONSTRAINT monitor_connections_sealed_key_id_check
                CHECK (sealed_key_id ~ '^ck1-[0-9a-f]{16}$'),
            ADD CONSTRAINT monitor_connections_sealed_pair CHECK (
                (credential_mode = 'sealed') = (sealed_ct IS NOT NULL AND sealed_key_id IS NOT NULL)
                AND (sealed_ct IS NULL) = (sealed_key_id IS NULL)
            ),
            ADD CONSTRAINT monitor_connections_sealed_kind
                CHECK (credential_mode <> 'sealed' OR kind = 'tines'),
            DROP CONSTRAINT monitor_connections_credential_mode_check,
            ADD CONSTRAINT monitor_connections_credential_mode_check
                CHECK (credential_mode IN ('key_file', 'sealed'))
    """)
    for body in (CREATE, REPLACE, RESEAL):
        op.execute(body)
    for signature in SIGNATURES:
        op.execute(f"REVOKE ALL ON FUNCTION execbound.{signature} FROM PUBLIC")
        for role in ("anon", "authenticated", "service_role"):
            if role_exists(role):
                op.execute(f"REVOKE ALL ON FUNCTION execbound.{signature} FROM {role}")
        op.execute(f"GRANT EXECUTE ON FUNCTION execbound.{signature} TO execbound_app")


def downgrade() -> None:
    op.execute("LOCK TABLE execbound.monitor_connections IN ACCESS EXCLUSIVE MODE")
    # The hosted owner does not bypass row security, so under FORCE this check would see no
    # tenant's rows and pass; lift it, as 0086's downgrade does, and put it back below.
    op.execute("ALTER TABLE execbound.monitor_connections NO FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security = off")
    if (
        op.get_bind()
        .execute(
            text(
                "SELECT EXISTS (SELECT 1 FROM execbound.monitor_connections "
                "WHERE credential_mode = 'sealed')"
            )
        )
        .scalar_one()
    ):
        raise RuntimeError("Cannot downgrade while a connection holds a sealed collection key")
    for signature in SIGNATURES:
        op.execute(f"DROP FUNCTION execbound.{signature}")
    op.execute("""
        ALTER TABLE execbound.monitor_connections
            DROP CONSTRAINT monitor_connections_credential_mode_check,
            ADD CONSTRAINT monitor_connections_credential_mode_check
                CHECK (credential_mode IN ('key_file')),
            DROP CONSTRAINT monitor_connections_sealed_kind,
            DROP CONSTRAINT monitor_connections_sealed_pair,
            DROP COLUMN sealed_key_id,
            DROP COLUMN sealed_ct
    """)
    op.execute("SET LOCAL row_security = on")
    op.execute("ALTER TABLE execbound.monitor_connections FORCE ROW LEVEL SECURITY")
