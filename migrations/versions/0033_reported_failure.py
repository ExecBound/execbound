"""A settled failure whose effect is not established, and the Arcade correlation table.

One migration carries both halves, because the control point's correlation row and the
state its post hook settles at are one change: the row binds one Arcade project's own
execution id to the ExecBound execution, which is how a redelivered hook is recognized as
the same one and how a post hook reaches the execution its pre hook opened.
"""

from alembic import op
from sqlalchemy import text

revision = "0033_reported_failure"
down_revision = "0032_connector_precondition"
branch_labels = None
depends_on = None

TENANT = "nullif((SELECT current_setting('execbound.tenant_id', true)), '')::uuid"
# The ten states admitted before this migration, in the order 0019 left them.
SETTLED_STATES = (
    "'ATTEMPTED', 'DENIED', 'PENDING_APPROVAL', 'RESERVED', 'DISPATCH_COMMITTED', "
    "'EXECUTED', 'FAILED_NOT_EXECUTED', 'INDETERMINATE', 'STALE_AUTHORIZATION', 'OBSERVED'"
)
REPORTED_FAILURE = "FAILED_EFFECT_UNKNOWN"
# Every column the state vocabulary is constrained on. The impact states are untouched:
# a settled reported failure writes CONFIRMED, which is the charge a success writes.
STATE_COLUMNS = (
    ("executions", "state"),
    ("execution_events", "from_state"),
    ("execution_events", "to_state"),
)
STATE_RLS_TABLES = ("executions", "execution_events")
# The tables the downgrade reads whole, so the lift covers the correlation table too: a
# schema owner without BYPASSRLS is subject to the forced policy exactly as the runtime is.
RLS_TABLES = ("arcade_hooks", *STATE_RLS_TABLES)
# The codes the hook contract admits in a result, which is the vocabulary of the
# extension's own answer; `OK` is the answer on which the tool call proceeds.
HOOK_CODES = "'OK', 'CHECK_FAILED', 'RATE_LIMIT_EXCEEDED'"
# The kernel's own idempotency key class, because the derived key is handed to admission
# and `execution_keys` refuses anything outside it.
IDEMPOTENCY_KEY = "^[A-Za-z0-9._:-]{1,128}$"
# The grant's report secret as `ReportSecret` admits it. A Gate secret is returned and
# never stored — `executions.owner_hash` keeps its SHA-256 digest — while this column holds
# a usable one, which is the trust boundary this carrier introduces and the design states.
REPORT_SECRET = "^[A-Za-z0-9_-]{32,128}$"
# The columns the runtime may move once the row exists. The row is inserted before the
# kernel call with what the hook body already carries; afterwards the pre path completes it
# with the kernel's answer, the post path records what the platform reported and nulls the
# secret at settlement, and the opportunistic clearing nulls the secret of a row whose
# report window has closed. The tenant, the principal, the Arcade execution id, the derived
# key, the tool identity, the reported metadata and user id and the creation time are
# outside this list and are therefore written once.
UPDATABLE = (
    "decision",
    "execution_id",
    "operation_id",
    "report_secret",
    "reported_success",
    "reported_code",
    "reported_error",
    "denial_contradiction_at",
    "inputs_contradiction_at",
    "settled_at",
)


def _state_checks(states: str) -> None:
    for table, column in STATE_COLUMNS:
        op.execute(
            f"ALTER TABLE execbound.{table} DROP CONSTRAINT {table}_{column}_check, "
            f"ADD CONSTRAINT {table}_{column}_check CHECK ({column} IN ({states}))"
        )


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
    _state_checks(SETTLED_STATES + f", '{REPORTED_FAILURE}'")
    # Correlation, not authority. No column here selects a mapping, chooses an action or a
    # target, sets a precondition class or promotes an evidence tier: the tool identity and
    # the reported strings are retained so an approver and an operator can read what the
    # platform said, and the map that decides is owner-provisioned configuration.
    #
    # The key is `(tenant_id, principal_id, arcade_execution_id)`, which is `execution_keys`'
    # own scope with Arcade's id in the place of the derived idempotency key. One Arcade
    # project is one ExecBound principal and `arcade_execution_id` is the platform's own
    # string, so two projects of one tenant can choose the same one with no misbehaviour
    # from either; a key without the principal would make the first project's row the row
    # the second project's hooks complete, record their decision on and read `held` off.
    op.execute(f"""
        CREATE TABLE execbound.arcade_hooks (
            tenant_id uuid NOT NULL REFERENCES execbound.tenants,
            arcade_execution_id text NOT NULL
                CHECK (length(arcade_execution_id) BETWEEN 1 AND 256),
            principal_id uuid NOT NULL,
            idempotency_key text NOT NULL CHECK (idempotency_key ~ '{IDEMPOTENCY_KEY}'),
            toolkit text NOT NULL CHECK (length(toolkit) BETWEEN 1 AND 128),
            tool_name text NOT NULL CHECK (length(tool_name) BETWEEN 1 AND 128),
            tool_version text NOT NULL CHECK (length(tool_version) BETWEEN 1 AND 64),
            reported_metadata jsonb
                CHECK (jsonb_typeof(reported_metadata) = 'object'),
            reported_user_id text CHECK (length(reported_user_id) BETWEEN 1 AND 256),
            created_at timestamptz NOT NULL,
            decision text CHECK (decision IN ({HOOK_CODES})),
            execution_id uuid,
            operation_id uuid,
            report_secret text CHECK (report_secret ~ '{REPORT_SECRET}'),
            reported_success boolean,
            reported_code text CHECK (length(reported_code) BETWEEN 1 AND 256),
            reported_error text CHECK (length(reported_error) BETWEEN 1 AND 2048),
            denial_contradiction_at timestamptz
                CONSTRAINT arcade_hooks_denial_contradiction_at_check
                CHECK (denial_contradiction_at >= created_at),
            inputs_contradiction_at timestamptz
                CONSTRAINT arcade_hooks_inputs_contradiction_at_check
                CHECK (inputs_contradiction_at >= created_at),
            settled_at timestamptz
                CONSTRAINT arcade_hooks_settled_at_check CHECK (settled_at >= created_at),
            PRIMARY KEY (tenant_id, principal_id, arcade_execution_id),
            FOREIGN KEY (tenant_id, principal_id) REFERENCES execbound.principals,
            FOREIGN KEY (tenant_id, execution_id) REFERENCES execbound.executions
        )
    """)
    _protect("arcade_hooks")
    # A row names the execution its pre hook opened once the kernel has answered. More than
    # one may name the same execution: a second Arcade id for a granted intent is adopted by
    # admission and refused for holding no secret, and its refusal is retained beside the
    # grant it was refused against. The index is non-unique for that reason, and it is also
    # the covering index the tenant-and-execution foreign key needs.
    #
    # There is no second index on the principal: the key's own leading
    # `(tenant_id, principal_id)` is what the tenant-and-principal foreign key covers and
    # what an operator reading one Arcade project's rows reads them by.
    op.execute(
        "CREATE INDEX arcade_hooks_execution ON execbound.arcade_hooks (tenant_id, execution_id)"
    )
    op.execute("GRANT SELECT, INSERT ON execbound.arcade_hooks TO execbound_app")
    op.execute(f"GRANT UPDATE ({', '.join(UPDATABLE)}) ON execbound.arcade_hooks TO execbound_app")


def downgrade() -> None:
    # Two conditions, both read over the whole database rather than one tenant, as a
    # migration must. The first is the correlation table itself: 0028 has no representation
    # for a control point's row, so dropping the table while one is retained would discard
    # ExecBound's record of which Arcade execution opened which ExecBound one.
    #
    # The second is about all three constrained state columns and not only
    # `executions.state`. A corrected row's own state is FAILED_NOT_EXECUTED while its
    # retained history holds an `execution_events` pair naming the new state in `to_state`
    # and then in `from_state`, so a downgrade that looked only at `executions` would drop a
    # constraint the event rows still violate. It refuses while any of the three holds the
    # value anywhere in the database.
    op.execute(
        "LOCK TABLE "
        + ", ".join(f"execbound.{table}" for table in RLS_TABLES)
        + " IN ACCESS EXCLUSIVE MODE"
    )
    for table in RLS_TABLES:
        op.execute(f"ALTER TABLE execbound.{table} NO FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security = off")
    bind = op.get_bind()
    correlated = bind.execute(
        text("SELECT EXISTS (SELECT 1 FROM execbound.arcade_hooks)")
    ).scalar_one()
    if correlated:
        raise RuntimeError("Cannot downgrade while an arcade correlation row is retained")
    held = " OR ".join(
        f"EXISTS (SELECT 1 FROM execbound.{table} WHERE {column} = :state)"
        for table, column in STATE_COLUMNS
    )
    retained = bind.execute(text(f"SELECT {held}"), {"state": REPORTED_FAILURE}).scalar_one()
    if retained:
        raise RuntimeError("Cannot downgrade while a reported failure is retained")
    _state_checks(SETTLED_STATES)
    op.execute("DROP TABLE execbound.arcade_hooks")
    # The state tables are restored; the correlation table is gone, so its lifted flag goes
    # with it rather than being set back on a table that no longer exists.
    for table in STATE_RLS_TABLES:
        op.execute(f"ALTER TABLE execbound.{table} FORCE ROW LEVEL SECURITY")
    # The second half of the pair 0026 lifts and restores, restored here for the same
    # reason it is there rather than for safety. A SET LOCAL dies with the transaction that
    # set it and `migrations/env.py` runs a whole alembic invocation in one, so leaving the
    # `off` above standing would hand it to the revisions this downgrade walks on to rather
    # than to anything outside the run. Restoring it keeps this revision's lift inside this
    # revision, which is the shape a reader of the two finds in 0026.
    op.execute("SET LOCAL row_security = on")
