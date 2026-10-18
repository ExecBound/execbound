"""Sample targets (#420): the `sample` flag, and the definer functions that install and remove.

An administrator's one click gives an empty workspace a real first governed action: one
connector account for the endpoint mock marked `sample`, its two context sources, the
`endpoint.isolate` mapping, three sample targets with their trusted facts, aliases and open
critical incidents, and the administrator's review scope on each. The runtime holds no write on
any of those tables, so `samples_install` writes them, and it is the only thing that ever sets
`sample`: no request field, header or credential attribute reaches the column. The facts come
from the caller, the product's `execbound.samples`, and are checked here for shape and domain;
the provider, the action and the mapping's versions are the catalog's and are written here.

`samples_remove` switches the same rows off and deletes nothing, refuses while any request on
the account is unresolved, and retires the starter bundle only while a space still selects it
and every mapping it names is this account's, which is what "still active and unchanged" means
for content that is immutable per bundle id.

Both functions take the tenant fence every admission takes and refuse anything but an active
administrator of an active tenant, checked once the fence is held so a principal switched off
while the call waited is refused. No table is added, so forced row-level security is unchanged;
the runtime's existing SELECT on `connector_accounts` covers the new column, and its only new
privilege is EXECUTE on the two functions.
"""

from alembic import op
from sqlalchemy import text

revision = "0060_sample_targets"
down_revision = "0059_workspace_invitations"
branch_labels = None
depends_on = None

SIGNATURES = (
    "samples_install(uuid, uuid, uuid, jsonb, timestamptz)",
    "samples_remove(uuid, uuid, uuid, timestamptz)",
)

INSTALL = r"""
CREATE FUNCTION execbound.samples_install(
    p_actor uuid, p_account uuid, p_space uuid, p_targets jsonb, p_now timestamptz)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_present uuid;
    v_inventory uuid := gen_random_uuid();
    v_incidents uuid := gen_random_uuid();
    v_mapping execbound.operation_mappings%ROWTYPE;
    v_remap boolean := false;
    v_target jsonb;
BEGIN
    IF v_tenant IS NULL OR p_actor IS NULL THEN
        RAISE EXCEPTION 'INVALID_ACTOR';
    END IF;
    IF p_now IS NULL OR abs(extract(epoch FROM (p_now - now()))) > 300 THEN
        RAISE EXCEPTION 'INVALID_CLOCK';
    END IF;
    -- The fence every admission of this tenant takes, so an install and a decision serialize.
    INSERT INTO execbound.tenant_policy_control(tenant_id, changed_at)
        VALUES (v_tenant, p_now) ON CONFLICT (tenant_id) DO NOTHING;
    PERFORM 1 FROM execbound.tenant_policy_control WHERE tenant_id = v_tenant FOR UPDATE;
    -- The actor is read under the fence, on a snapshot taken after any wait for it, so an
    -- administrator switched off while this call waited is refused.
    IF NOT execbound.access_has_permission(p_actor, 'workspace.manage', NULL, false) THEN
        RAISE EXCEPTION 'INVALID_ACTOR';
    END IF;
    -- A second install while samples are present returns what exists and changes nothing.
    SELECT a.account_id INTO v_present FROM execbound.connector_accounts a
     WHERE a.tenant_id = v_tenant AND a.sample AND a.active
     ORDER BY a.account_id LIMIT 1;
    IF v_present IS NOT NULL THEN
        RETURN jsonb_build_object('outcome', 'PRESENT', 'account_id', v_present);
    END IF;
    -- Offered only to a workspace with nothing a person built: no policy and no connection.
    IF EXISTS (SELECT 1 FROM execbound.space_policy_selection s WHERE s.tenant_id = v_tenant) THEN
        RAISE EXCEPTION 'POLICY_PRESENT';
    END IF;
    IF EXISTS (SELECT 1 FROM execbound.connector_accounts a
                WHERE a.tenant_id = v_tenant AND a.active) THEN
        RAISE EXCEPTION 'ACCOUNT_PRESENT';
    END IF;
    -- A mapping is keyed by its reference per tenant. A previous install's, left inactive by a
    -- removal, is re-pointed; one any other account holds is a person's and is never touched.
    SELECT * INTO v_mapping FROM execbound.operation_mappings m
     WHERE m.tenant_id = v_tenant AND m.operation_ref = 'endpoint.isolate' FOR UPDATE;
    IF FOUND THEN
        IF v_mapping.active OR NOT EXISTS (
            SELECT 1 FROM execbound.connector_accounts a
             WHERE a.tenant_id = v_tenant AND a.account_id = v_mapping.account_id AND a.sample)
        THEN
            RAISE EXCEPTION 'MAPPING_PRESENT';
        END IF;
        v_remap := true;
    END IF;
    IF p_account IS NULL OR p_space IS NULL OR NOT EXISTS (
        SELECT 1 FROM execbound.spaces s
         WHERE s.tenant_id = v_tenant AND s.space_id = p_space AND s.archived_at IS NULL) THEN
        RAISE EXCEPTION 'INVALID_SPACE';
    END IF;
    IF jsonb_typeof(p_targets) IS DISTINCT FROM 'array'
       OR jsonb_array_length(p_targets) NOT BETWEEN 1 AND 8 THEN
        RAISE EXCEPTION 'INVALID_TARGETS';
    END IF;
    BEGIN
        INSERT INTO execbound.connector_accounts
            (tenant_id, account_id, provider, space_id, sample)
        VALUES (v_tenant, p_account, 'mock_crowdstrike', p_space, true);
        INSERT INTO execbound.context_sources
            (tenant_id, account_id, source_id, kind, allowed_writers)
        VALUES (v_tenant, p_account, v_inventory, 'inventory', ARRAY['inventory_sync']),
               (v_tenant, p_account, v_incidents, 'incident', ARRAY['soc_analyst']);
        IF v_remap THEN
            UPDATE execbound.operation_mappings
               SET account_id = p_account, provider = 'mock_crowdstrike',
                   resource_type = 'endpoint', action = 'endpoint.isolate',
                   provider_operation = 'contain', mapping_version = 'sample-v1',
                   schema_version = 'action.v1',
                   context_contract_version = 'endpoint-isolation.v1', active = true
             WHERE tenant_id = v_tenant AND operation_ref = 'endpoint.isolate';
        ELSE
            INSERT INTO execbound.operation_mappings
                (tenant_id, operation_ref, account_id, provider, resource_type, action,
                 provider_operation, mapping_version, schema_version, context_contract_version)
            VALUES (v_tenant, 'endpoint.isolate', p_account, 'mock_crowdstrike', 'endpoint',
                    'endpoint.isolate', 'contain', 'sample-v1', 'action.v1',
                    'endpoint-isolation.v1');
        END IF;
        FOR v_target IN SELECT value FROM jsonb_array_elements(p_targets) LOOP
            IF coalesce(v_target->>'hostname', '') !~ '^[a-z0-9-]{1,40}\.sample\.invalid$'
               OR coalesce(v_target->>'provider_id', '') !~ '^sample-[a-z0-9-]{1,40}$'
               OR coalesce(v_target->>'role', '')
                  NOT IN ('workstation', 'server', 'domain_controller')
               OR coalesce(v_target->>'environment', '')
                  NOT IN ('development', 'staging', 'production')
               OR jsonb_typeof(v_target->'criticality') IS DISTINCT FROM 'number'
               OR (v_target->>'criticality')::integer NOT BETWEEN 0 AND 4
               OR coalesce(length(v_target->>'version'), 0) NOT BETWEEN 1 AND 80 THEN
                RAISE EXCEPTION 'INVALID_TARGETS';
            END IF;
            INSERT INTO execbound.canonical_targets(tenant_id, canonical_target_id, created_at)
            VALUES (v_tenant, (v_target->>'canonical_target_id')::uuid, p_now);
            INSERT INTO execbound.resources
                (tenant_id, account_id, provider, resource_type, resource_id, provider_id,
                 version, source_id, role, environment, criticality, observed_at)
            VALUES (v_tenant, p_account, 'mock_crowdstrike', 'endpoint',
                    (v_target->>'resource_id')::uuid, v_target->>'provider_id',
                    v_target->>'version', v_inventory, v_target->>'role',
                    v_target->>'environment', (v_target->>'criticality')::integer, p_now);
            INSERT INTO execbound.resource_identities
                (tenant_id, account_id, provider, resource_type, resource_id,
                 canonical_target_id)
            VALUES (v_tenant, p_account, 'mock_crowdstrike', 'endpoint',
                    (v_target->>'resource_id')::uuid,
                    (v_target->>'canonical_target_id')::uuid);
            INSERT INTO execbound.resource_aliases
                (tenant_id, alias_id, account_id, provider, resource_type, kind,
                 normalized_value, resource_id, valid_from, expires_at)
            VALUES (v_tenant, gen_random_uuid(), p_account, 'mock_crowdstrike', 'endpoint',
                    'provider_id', v_target->>'provider_id', (v_target->>'resource_id')::uuid,
                    p_now, p_now + interval '365 days'),
                   (v_tenant, gen_random_uuid(), p_account, 'mock_crowdstrike', 'endpoint',
                    'hostname', v_target->>'hostname', (v_target->>'resource_id')::uuid,
                    p_now, p_now + interval '365 days');
            INSERT INTO execbound.incidents
                (tenant_id, account_id, provider, resource_type, incident_id, resource_id,
                 source_id, version, status, severity, observed_at)
            VALUES (v_tenant, p_account, 'mock_crowdstrike', 'endpoint',
                    (v_target->>'incident_id')::uuid, (v_target->>'resource_id')::uuid,
                    v_incidents, 'incident-v1', 'OPEN', 'CRITICAL', p_now);
            INSERT INTO execbound.approval_scopes
                (tenant_id, approver_id, canonical_target_id, action, space_id)
            VALUES (v_tenant, p_actor, (v_target->>'canonical_target_id')::uuid,
                    'endpoint.isolate', p_space);
        END LOOP;
    EXCEPTION WHEN unique_violation OR foreign_key_violation OR not_null_violation
                   OR check_violation OR invalid_text_representation THEN
        RAISE EXCEPTION 'INVALID_TARGETS';
    END;
    RETURN jsonb_build_object('outcome', 'INSTALLED', 'account_id', p_account);
END $$
"""

REMOVE = r"""
CREATE FUNCTION execbound.samples_remove(
    p_actor uuid, p_account uuid, p_bundle uuid, p_now timestamptz)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_spaces uuid[] := '{}';
    v_retired boolean := false;
BEGIN
    IF v_tenant IS NULL OR p_actor IS NULL THEN
        RAISE EXCEPTION 'INVALID_ACTOR';
    END IF;
    IF p_now IS NULL OR abs(extract(epoch FROM (p_now - now()))) > 300 THEN
        RAISE EXCEPTION 'INVALID_CLOCK';
    END IF;
    INSERT INTO execbound.tenant_policy_control(tenant_id, changed_at)
        VALUES (v_tenant, p_now) ON CONFLICT (tenant_id) DO NOTHING;
    PERFORM 1 FROM execbound.tenant_policy_control WHERE tenant_id = v_tenant FOR UPDATE;
    IF NOT execbound.access_has_permission(p_actor, 'workspace.manage', NULL, false) THEN
        RAISE EXCEPTION 'INVALID_ACTOR';
    END IF;
    PERFORM 1 FROM execbound.connector_accounts a
     WHERE a.tenant_id = v_tenant AND a.account_id = p_account AND a.sample AND a.active
       FOR UPDATE;
    IF NOT FOUND THEN
        RETURN jsonb_build_object('outcome', 'ABSENT');
    END IF;
    -- Never strand a request: nothing leaves while one on this account is unresolved.
    IF EXISTS (
        SELECT 1 FROM execbound.executions e
         WHERE e.tenant_id = v_tenant
           AND e.state IN ('ATTEMPTED', 'PENDING_APPROVAL', 'RESERVED',
                           'DISPATCH_COMMITTED', 'INDETERMINATE')
           AND e.frozen #>> '{intent,account_id}' = p_account::text) THEN
        RAISE EXCEPTION 'SAMPLES_BUSY';
    END IF;
    UPDATE execbound.connector_accounts SET active = false
     WHERE tenant_id = v_tenant AND account_id = p_account;
    UPDATE execbound.context_sources SET active = false
     WHERE tenant_id = v_tenant AND account_id = p_account;
    UPDATE execbound.operation_mappings SET active = false
     WHERE tenant_id = v_tenant AND account_id = p_account;
    UPDATE execbound.resources SET active = false
     WHERE tenant_id = v_tenant AND account_id = p_account;
    UPDATE execbound.approval_scopes s SET active = false
      FROM execbound.resource_identities i
     WHERE s.tenant_id = v_tenant AND i.tenant_id = v_tenant AND i.account_id = p_account
       AND s.canonical_target_id = i.canonical_target_id AND s.action = 'endpoint.isolate';
    -- The starter bundle leaves with its samples only while it is still what the tenant runs,
    -- unchanged: a space still selects it and every mapping it names is this account's.
    IF p_bundle IS NOT NULL AND EXISTS (
        SELECT 1 FROM execbound.policy_bundle_contents c
         WHERE c.tenant_id = v_tenant AND c.bundle_id = p_bundle
           AND jsonb_typeof(c.content->'mappings') = 'array'
           AND jsonb_array_length(c.content->'mappings') > 0
           AND NOT EXISTS (
               SELECT 1 FROM jsonb_array_elements(c.content->'mappings') m
                WHERE m->>'account_id' IS DISTINCT FROM p_account::text)) THEN
        SELECT coalesce(array_agg(s.space_id ORDER BY s.space_id), '{}') INTO v_spaces
          FROM execbound.space_policy_selection s
         WHERE s.tenant_id = v_tenant AND s.bundle_id = p_bundle;
        IF cardinality(v_spaces) > 0 THEN
            DELETE FROM execbound.space_policy_selection
             WHERE tenant_id = v_tenant AND bundle_id = p_bundle;
            UPDATE execbound.policy_bundle_lifecycle SET state = 'RETIRED', changed_at = p_now
             WHERE tenant_id = v_tenant AND bundle_id = p_bundle;
            v_retired := true;
        END IF;
    END IF;
    RETURN jsonb_build_object('outcome', 'REMOVED', 'account_id', p_account,
                              'retired', v_retired, 'spaces', to_jsonb(v_spaces));
END $$
"""


def upgrade() -> None:
    # ADD COLUMN with a default fills every existing row whatever row-level security says, so
    # no lift is needed, and every account that exists stays an ordinary one.
    op.execute(
        "ALTER TABLE execbound.connector_accounts ADD COLUMN sample boolean NOT NULL DEFAULT false"
    )
    for body in (INSTALL, REMOVE):
        op.execute(body)
    for signature in SIGNATURES:
        op.execute(f"REVOKE ALL ON FUNCTION execbound.{signature} FROM PUBLIC")
        op.execute(f"GRANT EXECUTE ON FUNCTION execbound.{signature} TO execbound_app")


def downgrade() -> None:
    # A sample account has no representation before 0060, and dropping the flag would turn it
    # into an ordinary account nothing configured. The guard reads every tenant, so row-level
    # security is lifted on the one table around it, under a lock, as 0056 does.
    op.execute("LOCK TABLE execbound.connector_accounts IN ACCESS EXCLUSIVE MODE")
    op.execute("ALTER TABLE execbound.connector_accounts NO FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security = off")
    retained = (
        op.get_bind()
        .execute(text("SELECT EXISTS (SELECT 1 FROM execbound.connector_accounts WHERE sample)"))
        .scalar_one()
    )
    op.execute("ALTER TABLE execbound.connector_accounts FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security = on")
    if retained:
        raise RuntimeError("Cannot downgrade while sample connector accounts exist")
    for signature in SIGNATURES:
        op.execute(f"DROP FUNCTION execbound.{signature}")
    op.execute("ALTER TABLE execbound.connector_accounts DROP COLUMN sample")
