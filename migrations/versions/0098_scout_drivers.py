# SPDX-License-Identifier: AGPL-3.0-only
"""Scout's driver evidence: who drives a non-human actor, and how that is known (#355).

`monitor_actor_drivers` holds one row per actor, evidence level, platform and source connection,
under forced row security:

- `evidence` is `declared` (the directory names the driver: the AI publisher catalog's entry for
  the principal's application, or an agent identity's blueprint), `network` (its sign-ins come
  from a range the reviewed egress catalog attributes to a platform, or from an address an
  administrator recorded as the Space's Tines tenant's egress) or `joined` (that Tines network
  evidence, plus the Tines tenant's credentials allowed to call Microsoft Graph or Microsoft
  sign-in and the stories that use them). An actor with none of them is unattributed, which is
  the absence of a row.
- `platform_ref` says what the row names by its prefix: `publisher:` or `egress:` and a catalog
  key, `blueprint:` and the blueprint's application id, or `tines:` and a Tines connection's id.
  Its shape is checked against its level.
- `detail_refs` holds Tines story ids and nothing else, at most 100 and only on a `joined` row,
  and `detail_capped` says the list is "at least": Tines lists at most 100 actions referencing a
  credential, and the row keeps at most 100 stories. No name is kept.
- `catalog_version` names the catalog revision a catalog-derived row came from.
- `first_seen_at`, `last_seen_at` and `gone_at` date the evidence. A row is marked gone, never
  deleted; the runtime holds `SELECT`, `INSERT` and column `UPDATE` on the moving columns and no
  `DELETE`.

`monitor_connections` gains, for an Entra connection, `sign_in_cursor`, where the next read of
the directory's service principal sign-ins starts, which the runtime updates and does not insert;
and for a Tines connection `egress_addresses`, one to eight single public addresses an
administrator of its Space recorded as the Tines tenant's egress, with `egress_recorded_at` and
`egress_recorded_by`. `admin_set_egress_addresses` is the only writer of the three: an active
administrator of the connection's Space, a Tines connection, at most eight host addresses, none in
a private, shared, loopback, link-local, documentation, benchmarking, multicast or reserved block.
The runtime may update none of them.

`monitor_inventory` gains, on a credential row only, `host_scope` (`microsoft` when its allowed
hosts name Microsoft Graph or Microsoft sign-in, `other` when they name only other hosts,
`unrestricted` when they name none), `story_refs` (the stories that reference it, at most 100)
and `references_capped` (Tines' own cap of 100 actions was reached). No host is kept.

`monitor_agents` gains `user_agent_hint`, the leading product token of the user agent the
principal's newest successful sign-in sent, and `user_agent_seen_at`. A client chooses its user
agent, so it is a hint that never makes a driver row.

The downgrade refuses `SCOUT_DRIVERS_RETAINED` while any driver row or recorded egress address is
retained, looking with row security off for the look alone because an owner that does not bypass
it would otherwise see nothing. It otherwise drops the table, the function and the columns; a
cursor, a credential's scope and story references, and a user agent hint are state rather than
evidence.
"""

from alembic import op
from sqlalchemy import text

revision = "0098_scout_drivers"
down_revision = "0097_findings_destinations"
branch_labels = None
depends_on = None

GUID = "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
KEY = "[a-z][a-z0-9-]{0,31}"
# The platform a row names, by its prefix: a catalog key, a blueprint's application id, or a
# Tines connection's id (a UUID, written in lower case as PostgreSQL writes one).
PLATFORM = f"^((publisher|egress):{KEY}|blueprint:{GUID}|tines:{GUID})$"
# Tines story ids as the collector keeps an identifier, joined by commas, which none holds; and
# exactly one comma fewer than there are ids, so no id can carry one and none can be null.
STORY = "[A-Za-z0-9._:-]{1,96}"


def _stories(column: str) -> str:
    joined = f"array_to_string({column}, ',')"
    return (
        f"({joined} ~ '^{STORY}(,{STORY})*$' "
        f"AND length({joined}) - length(replace({joined}, ',', '')) = cardinality({column}) - 1)"
    )


SUPABASE_ROLES = ("anon", "authenticated", "service_role")
SIGNATURE = "admin_set_egress_addresses(uuid, uuid, inet[])"
DRIVER_UPDATES = "first_seen_at, last_seen_at, gone_at, detail_refs, detail_capped, catalog_version"
INVENTORY_COLUMNS = ("host_scope", "story_refs", "references_capped")
AGENT_COLUMNS = ("user_agent_hint", "user_agent_seen_at")
TENANT = "nullif((SELECT current_setting('execbound.tenant_id', true)), '')::uuid"

TABLE = f"""
CREATE TABLE execbound.monitor_actor_drivers (
    tenant_id uuid NOT NULL,
    agent_id uuid NOT NULL,
    evidence text NOT NULL CHECK (evidence IN ('declared', 'network', 'joined')),
    platform_ref text NOT NULL CHECK (platform_ref ~ '{PLATFORM}'),
    source_connection_id uuid NOT NULL,
    detail_refs text[] NOT NULL DEFAULT '{{}}',
    detail_capped boolean NOT NULL DEFAULT false,
    catalog_version text CHECK (catalog_version ~ '^[a-z][a-z0-9.-]{{0,47}}$'),
    first_seen_at timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL,
    gone_at timestamptz,
    PRIMARY KEY (tenant_id, agent_id, evidence, platform_ref, source_connection_id),
    FOREIGN KEY (tenant_id, agent_id) REFERENCES execbound.monitor_agents (tenant_id, agent_id),
    FOREIGN KEY (tenant_id, source_connection_id)
        REFERENCES execbound.monitor_connections (tenant_id, connection_id),
    CHECK (last_seen_at >= first_seen_at),
    CHECK (gone_at IS NULL OR gone_at >= first_seen_at),
    -- What each level may name: the directory declares a publisher or a blueprint, a network
    -- match names a catalogued platform or the Space's Tines tenant, and a join only that.
    CHECK ((evidence = 'declared') = (platform_ref ~ '^(publisher|blueprint):')),
    CHECK (evidence <> 'network' OR platform_ref ~ '^(egress|tines):'),
    CHECK (evidence <> 'joined' OR platform_ref ~ '^tines:'),
    -- Story ids are a join's alone, at most 100 of them, and nothing but identifiers.
    CHECK (cardinality(detail_refs) <= 100),
    CHECK (cardinality(detail_refs) = 0 OR (evidence = 'joined' AND {_stories("detail_refs")})),
    CHECK (NOT detail_capped OR evidence = 'joined')
);
CREATE INDEX monitor_actor_drivers_source
    ON execbound.monitor_actor_drivers (tenant_id, source_connection_id);
"""

# The blocks no Tines tenant's egress can be in, from IANA's special-purpose address registries:
# private, shared, loopback, link-local, documentation, benchmarking, multicast and reserved
# space, and everything outside IPv6 global unicast. The store refuses an address in any of them
# before it calls the function, from the same list (`monitoring.drivers.NOT_EGRESS`); this is the
# database's copy of it.
RESERVED = (
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.88.99.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
    # Outside 2000::/3: unspecified, loopback, IPv4-mapped and translated, discard-only, segment
    # routing, unique-local, link-local, multicast and unallocated space.
    "::/3",
    "4000::/2",
    "8000::/1",
    "2001::/23",
    "2001:db8::/32",
    "2002::/16",
    "3fff::/20",
)
RESERVED_SQL = "ARRAY[" + ", ".join(f"'{block}'" for block in RESERVED) + "]::inet[]"

SET_EGRESS = f"""
CREATE FUNCTION execbound.admin_set_egress_addresses(
    p_actor uuid, p_connection uuid, p_addresses inet[])
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_kind text;
    v_space uuid;
BEGIN
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
    SELECT c.kind, c.space_id INTO v_kind, v_space FROM execbound.monitor_connections c
     WHERE c.tenant_id = v_tenant AND c.connection_id = p_connection AND c.active
       FOR UPDATE;
    IF v_kind IS NULL THEN
        RAISE EXCEPTION 'INVALID_STATE';
    END IF;
    -- A membership narrows the tenant's ADMIN to the Spaces it administers (0086's rule).
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
    IF v_kind <> 'tines' THEN
        RAISE EXCEPTION 'INVALID_STATE';
    END IF;
    -- None or empty clears the record. Otherwise one to eight distinct single addresses, none
    -- in a block no tenant's egress can be in.
    IF p_addresses IS NOT NULL AND cardinality(p_addresses) > 0 AND (
        cardinality(p_addresses) > 8
        OR array_position(p_addresses, NULL) IS NOT NULL
        OR (SELECT count(DISTINCT a) FROM unnest(p_addresses) AS a) <> cardinality(p_addresses)
        OR EXISTS (
            SELECT 1 FROM unnest(p_addresses) AS a
             WHERE masklen(a) <> CASE family(a) WHEN 4 THEN 32 ELSE 128 END
                OR EXISTS (SELECT 1 FROM unnest({RESERVED_SQL}) AS r WHERE a <<= r)
        )
    ) THEN
        RAISE EXCEPTION 'INVALID_EGRESS';
    END IF;
    UPDATE execbound.monitor_connections
       SET egress_addresses = CASE WHEN cardinality(p_addresses) > 0 THEN
                                  (SELECT array_agg(a ORDER BY a) FROM unnest(p_addresses) a)
                              END,
           egress_recorded_at = now(),
           egress_recorded_by = p_actor
     WHERE tenant_id = v_tenant AND connection_id = p_connection;
END $$
"""


def _role_exists(role: str) -> bool:
    return bool(
        op.get_bind()
        .execute(text("SELECT 1 FROM pg_roles WHERE rolname = :role"), {"role": role})
        .scalar()
    )


def upgrade() -> None:
    op.execute(TABLE)
    op.execute("ALTER TABLE execbound.monitor_actor_drivers ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE execbound.monitor_actor_drivers FORCE ROW LEVEL SECURITY")
    op.execute(f"""
        CREATE POLICY tenant_isolation ON execbound.monitor_actor_drivers
        USING (tenant_id = {TENANT}) WITH CHECK (tenant_id = {TENANT})
    """)
    op.execute("REVOKE ALL ON execbound.monitor_actor_drivers FROM PUBLIC")
    for role in SUPABASE_ROLES:
        if _role_exists(role):
            op.execute(f"REVOKE ALL ON execbound.monitor_actor_drivers FROM {role}")
    op.execute("GRANT SELECT, INSERT ON execbound.monitor_actor_drivers TO execbound_app")
    op.execute(
        f"GRANT UPDATE ({DRIVER_UPDATES}) ON execbound.monitor_actor_drivers TO execbound_app"
    )
    op.execute("""
        ALTER TABLE execbound.monitor_connections
            ADD COLUMN sign_in_cursor timestamptz,
            ADD COLUMN egress_addresses inet[],
            ADD COLUMN egress_recorded_at timestamptz,
            ADD COLUMN egress_recorded_by uuid,
            ADD CONSTRAINT monitor_connections_sign_in_kind
                CHECK (sign_in_cursor IS NULL OR kind = 'entra_agent_id'),
            ADD CONSTRAINT monitor_connections_egress_kind
                CHECK (egress_addresses IS NULL OR (kind = 'tines'
                    AND cardinality(egress_addresses) BETWEEN 1 AND 8)),
            ADD CONSTRAINT monitor_connections_egress_recorded
                CHECK ((egress_recorded_at IS NULL) = (egress_recorded_by IS NULL)
                    AND (egress_addresses IS NULL OR egress_recorded_at IS NOT NULL)),
            ADD CONSTRAINT monitor_connections_egress_recorded_by_fkey
                FOREIGN KEY (tenant_id, egress_recorded_by)
                REFERENCES execbound.principals(tenant_id, principal_id)
    """)
    op.execute(
        "CREATE INDEX monitor_connections_egress_recorded_by "
        "ON execbound.monitor_connections (tenant_id, egress_recorded_by)"
    )
    op.execute("GRANT UPDATE (sign_in_cursor) ON execbound.monitor_connections TO execbound_app")
    op.execute(SET_EGRESS)
    op.execute(f"REVOKE ALL ON FUNCTION execbound.{SIGNATURE} FROM PUBLIC")
    for role in SUPABASE_ROLES:
        if _role_exists(role):
            op.execute(f"REVOKE ALL ON FUNCTION execbound.{SIGNATURE} FROM {role}")
    op.execute(f"GRANT EXECUTE ON FUNCTION execbound.{SIGNATURE} TO execbound_app")
    op.execute(f"""
        ALTER TABLE execbound.monitor_inventory
            ADD COLUMN host_scope text
                CHECK (host_scope IN ('microsoft', 'other', 'unrestricted')),
            ADD COLUMN story_refs text[],
            ADD COLUMN references_capped boolean,
            ADD CONSTRAINT monitor_inventory_credential_scope CHECK (
                item_kind = 'credential'
                OR (host_scope IS NULL AND story_refs IS NULL AND references_capped IS NULL)
            ),
            ADD CONSTRAINT monitor_inventory_story_refs CHECK (
                story_refs IS NULL OR (cardinality(story_refs) <= 100
                    AND (cardinality(story_refs) = 0 OR {_stories("story_refs")}))
            )
    """)
    op.execute(
        "GRANT UPDATE (host_scope, story_refs, references_capped) "
        "ON execbound.monitor_inventory TO execbound_app"
    )
    op.execute("""
        ALTER TABLE execbound.monitor_agents
            ADD COLUMN user_agent_hint text
                CHECK (user_agent_hint ~ '^[A-Za-z][A-Za-z0-9._-]{0,47}(/[A-Za-z0-9._-]{1,32})?$'),
            ADD COLUMN user_agent_seen_at timestamptz,
            ADD CONSTRAINT monitor_agents_user_agent_pair
                CHECK ((user_agent_hint IS NULL) = (user_agent_seen_at IS NULL))
    """)
    op.execute(
        "GRANT UPDATE (user_agent_hint, user_agent_seen_at) "
        "ON execbound.monitor_agents TO execbound_app"
    )


def downgrade() -> None:
    op.execute(
        "LOCK TABLE execbound.monitor_actor_drivers, execbound.monitor_connections "
        "IN ACCESS EXCLUSIVE MODE"
    )
    # The look sees every tenant: the hosted owner does not bypass row security.
    for table in ("monitor_actor_drivers", "monitor_connections"):
        op.execute(f"ALTER TABLE execbound.{table} NO FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security = off")
    retained = (
        op.get_bind()
        .execute(
            text(
                "SELECT EXISTS (SELECT 1 FROM execbound.monitor_actor_drivers) "
                "OR EXISTS (SELECT 1 FROM execbound.monitor_connections "
                "WHERE egress_addresses IS NOT NULL)"
            )
        )
        .scalar_one()
    )
    op.execute("SET LOCAL row_security = on")
    for table in ("monitor_actor_drivers", "monitor_connections"):
        op.execute(f"ALTER TABLE execbound.{table} FORCE ROW LEVEL SECURITY")
    if retained:
        raise RuntimeError(
            "SCOUT_DRIVERS_RETAINED: driver evidence or a recorded egress address is retained, "
            "and the earlier schema cannot hold it"
        )
    op.execute(f"DROP FUNCTION execbound.{SIGNATURE}")
    op.execute("DROP TABLE execbound.monitor_actor_drivers")
    op.execute("DROP INDEX execbound.monitor_connections_egress_recorded_by")
    op.execute("""
        ALTER TABLE execbound.monitor_connections
            DROP CONSTRAINT monitor_connections_egress_recorded_by_fkey,
            DROP CONSTRAINT monitor_connections_egress_recorded,
            DROP CONSTRAINT monitor_connections_egress_kind,
            DROP CONSTRAINT monitor_connections_sign_in_kind,
            DROP COLUMN egress_recorded_by,
            DROP COLUMN egress_recorded_at,
            DROP COLUMN egress_addresses,
            DROP COLUMN sign_in_cursor
    """)
    op.execute(
        "ALTER TABLE execbound.monitor_inventory "
        + ", ".join(
            [
                "DROP CONSTRAINT monitor_inventory_story_refs",
                "DROP CONSTRAINT monitor_inventory_credential_scope",
                *(f"DROP COLUMN {column}" for column in reversed(INVENTORY_COLUMNS)),
            ]
        )
    )
    op.execute(
        "ALTER TABLE execbound.monitor_agents "
        + ", ".join(
            [
                "DROP CONSTRAINT monitor_agents_user_agent_pair",
                *(f"DROP COLUMN {column}" for column in reversed(AGENT_COLUMNS)),
            ]
        )
    )
