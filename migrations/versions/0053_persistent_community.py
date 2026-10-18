"""Persistent Community claims; legacy lifecycle timestamps remain historical evidence."""

import importlib.util
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from alembic import op
from sqlalchemy import text
from sqlalchemy.engine import Connection

revision = "0053_persistent_community"
down_revision = "0052_account_experience"
branch_labels = None
depends_on = None


def previous(name: str, filename: str = "0044_hosted_free.py") -> str:
    spec = importlib.util.spec_from_file_location(
        "community_previous", Path(__file__).with_name(filename)
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return str(getattr(module, name)).replace("CREATE FUNCTION", "CREATE OR REPLACE FUNCTION", 1)


def backfill(connection: Connection) -> None:
    """Idempotent owner backfill, called with these tables locked and owner RLS lifted."""
    connection.execute(
        text("""
        UPDATE execbound.onboarding_slots SET community_at = now()
        WHERE claimed_at IS NOT NULL AND community_at IS NULL
    """)
    )
    # Existing uncapped team workspaces keep their entitlements. No principal is changed.
    connection.execute(text("UPDATE execbound.tenants SET plan = 'free' WHERE plan = 'sandbox'"))


EXPIRY_TRIGGER = """
CREATE OR REPLACE FUNCTION execbound.onboarding_slot_expiry()
RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NEW.community_at IS NULL THEN
        NEW.expires_at := CASE WHEN NEW.claimed_at IS NULL THEN NULL
            ELSE NEW.claimed_at + interval '14 days' END;
    END IF;
    RETURN NEW;
END $$
"""


def fixture_id(seed: str, label: str) -> str:
    # Frozen v1 fixture identity scheme. Never infer provenance from a display name.
    return str(uuid5(NAMESPACE_URL, f"https://execbound.invalid/validation/v1/{seed}/{label}"))


def backfill_fixtures(connection: Connection) -> None:
    """Recognize untouched owner seeds, not adopted/imported records.

    Original seeds created no row-backed facts. Those remain unclassified. A context import
    disqualifies its whole account, even if it happened to write the original values again.
    Updated or uncertain rows remain untouched and are visible in the owner report.
    """
    slots = connection.execute(
        text("""SELECT s.tenant_id, s.seed FROM
        execbound.onboarding_slots s WHERE EXISTS (SELECT 1 FROM execbound.audit_events e
        WHERE e.tenant_id=s.tenant_id AND e.kind='sandbox.seeded'
          AND e.payload->>'seed'=s.seed AND e.payload->>'slot'=s.slot::text)""")
    ).all()
    specs = [
        (
            f"workstation-{i:02}",
            "endpoint",
            "workstation",
            None,
            "production" if i == 25 else "development",
        )
        for i in range(1, 26)
    ] + [("domain-controller", "endpoint", "domain_controller", None, "production")]
    specs += [
        (label, "identity", None, privilege, environment)
        for label, privilege, environment in (
            ("identity-disable", "standard", "development"),
            ("identity-enable", "standard", "development"),
            ("identity-revoke-sessions", "standard", "development"),
            ("identity-production", "standard", "production"),
            ("identity-privileged", "privileged", "production"),
            ("identity-tier0", "tier0", "production"),
        )
    ]
    for tenant, seed in slots:
        for label, kind, role, privilege, environment in specs:
            provider = "mock_crowdstrike" if kind == "endpoint" else "mock_entra"
            account = fixture_id(seed, f"{tenant}/{provider}/account")
            params = {
                "t": tenant,
                "a": account,
                "p": provider,
                "k": kind,
                "r": fixture_id(seed, f"{tenant}/{label}/resource"),
                "label": label,
                "role": role,
                "privilege": privilege,
                "environment": environment,
                "source": fixture_id(seed, f"{account}/inventory"),
                "incident": fixture_id(seed, f"{tenant}/{label}/incident"),
                "incident_source": fixture_id(seed, f"{account}/incident-source"),
            }
            connection.execute(
                text("""UPDATE execbound.resources r SET demo_fixture=true
                WHERE tenant_id=:t AND account_id=:a AND provider=:p AND resource_type=:k
                  AND resource_id=:r AND provider_id=:label AND source_id=:source
                  AND role IS NOT DISTINCT FROM :role
                  AND privilege_class IS NOT DISTINCT FROM :privilege
                  AND environment=:environment AND criticality=1 AND version='resource-v1'
                  AND active AND NOT demo_fixture AND NOT EXISTS (
                    SELECT 1 FROM execbound.audit_events e WHERE e.tenant_id=:t
                    AND e.kind='context.imported' AND e.payload->>'account_id'=CAST(:a AS text))
            """),
                params,
            )
            connection.execute(
                text("""UPDATE execbound.incidents i SET demo_fixture=true
                WHERE tenant_id=:t AND account_id=:a AND provider=:p AND resource_type=:k
                  AND resource_id=:r AND incident_id=:incident AND source_id=:incident_source
                  AND version='incident-v1' AND status='OPEN' AND severity='CRITICAL'
                  AND NOT demo_fixture AND EXISTS (SELECT 1 FROM execbound.resources r
                    WHERE r.tenant_id=i.tenant_id AND r.account_id=i.account_id
                      AND r.provider=i.provider AND r.resource_type=i.resource_type
                      AND r.resource_id=i.resource_id AND r.demo_fixture)
                  AND NOT EXISTS (SELECT 1 FROM execbound.audit_events e WHERE e.tenant_id=:t
                    AND e.kind='context.imported' AND e.payload->>'account_id'=CAST(:a AS text))
            """),
                params,
            )


def live_function(name: str) -> str:
    """Patch the installed predecessor, including later access-control fences."""
    return str(
        op.get_bind()
        .execute(
            text("""SELECT pg_get_functiondef(p.oid)
        FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
        WHERE n.nspname='execbound' AND p.proname=:name"""),
            {"name": name},
        )
        .scalar_one()
    )


def replace_once(body: str, old: str, new: str, *, reverse: bool = False) -> str:
    if reverse:
        old, new = new, old
    assert body.count(old) == 1, "Unexpected predecessor function definition"
    return body.replace(old, new, 1)


def fixture_refresh(body: str, *, reverse: bool = False) -> str:
    patches = [
        (
            "WHERE r2.tenant_id = v_tenant)",
            "WHERE r2.tenant_id = v_tenant AND r2.demo_fixture "
            "AND r2.provider IN ('mock_crowdstrike', 'mock_entra'))",
        ),
        (
            "AND r.resource_id = v.resource_id;",
            "AND r.resource_id = v.resource_id AND r.demo_fixture;",
        ),
        (
            "    UPDATE execbound.resources r",
            "    PERFORM 1 FROM execbound.tenants WHERE tenant_id=v_tenant FOR UPDATE;\n"
            "    UPDATE execbound.resources r",
        ),
    ]
    for table in ("resource_facts", "incidents"):
        patches.append(
            (
                f"UPDATE execbound.{table} SET observed_at = now() WHERE tenant_id = v_tenant;",
                f"""UPDATE execbound.{table} child SET observed_at=now()
            FROM execbound.resources parent
            WHERE child.tenant_id=v_tenant AND child.demo_fixture
              AND parent.tenant_id=child.tenant_id AND parent.account_id=child.account_id
              AND parent.provider=child.provider AND parent.resource_type=child.resource_type
              AND parent.resource_id=child.resource_id AND parent.demo_fixture
              AND parent.provider IN ('mock_crowdstrike','mock_entra');""",
            )
        )
    for old, new in reversed(patches) if reverse else patches:
        body = replace_once(body, old, new, reverse=reverse)
    return body


def claim_function(*, reverse: bool = False) -> str:
    body = live_function("onboarding_claim")
    body = replace_once(body, "plan = 'sandbox'", "plan = 'free'", reverse=reverse)
    return replace_once(
        body,
        "SET claimed_at = now()",
        "SET claimed_at = now(), community_at = now()",
        reverse=reverse,
    )


def trial_function(name: str, *, reverse: bool = False) -> str:
    marker = "IF NOT FOUND OR v_slot.claimed_at IS NULL"
    return replace_once(
        live_function(name), marker, marker + " OR v_slot.community_at IS NOT NULL", reverse=reverse
    )


def upgrade() -> None:
    for table in ("resources", "resource_facts", "incidents"):
        op.execute(
            f"ALTER TABLE execbound.{table} ADD COLUMN demo_fixture boolean NOT NULL DEFAULT false"
        )
    op.execute(fixture_refresh(live_function("sandbox_reattest")))
    op.execute("ALTER TABLE execbound.onboarding_slots ADD COLUMN community_at timestamptz")
    op.execute("""ALTER TABLE execbound.onboarding_slots ADD CONSTRAINT community_claimed
        CHECK (community_at IS NULL OR claimed_at IS NOT NULL)""")
    op.execute(EXPIRY_TRIGGER)
    op.execute(claim_function())
    for name in ("sandbox_expire", "sandbox_notice", "sandbox_fallback"):
        op.execute(trial_function(name))
    tables = (
        "tenants",
        "onboarding_slots",
        "resources",
        "resource_facts",
        "incidents",
        "audit_events",
    )
    op.execute(
        "LOCK TABLE " + ", ".join(f"execbound.{t}" for t in tables) + " IN ACCESS EXCLUSIVE MODE"
    )
    for table in tables:
        op.execute(f"ALTER TABLE execbound.{table} NO FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security = off")
    backfill(op.get_bind())
    backfill_fixtures(op.get_bind())
    for table in tables:
        op.execute(f"ALTER TABLE execbound.{table} FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security = on")


def downgrade() -> None:
    # A downgrade must not silently re-arm historic trial deadlines or unbound refresh.
    # Restore a pre-transition backup in an isolated database if a rollback is necessary.
    op.execute("LOCK TABLE execbound.onboarding_slots IN ACCESS EXCLUSIVE MODE")
    op.execute("ALTER TABLE execbound.onboarding_slots NO FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security=off")
    if (
        op.get_bind()
        .execute(
            text(
                "SELECT EXISTS(SELECT 1 FROM execbound.onboarding_slots "
                "WHERE claimed_at IS NOT NULL)"
            )
        )
        .scalar_one()
    ):
        raise RuntimeError(
            "Community history requires a reviewed restore; automatic downgrade refused"
        )
    op.execute(claim_function(reverse=True))
    for name in ("sandbox_expire", "sandbox_notice", "sandbox_fallback"):
        op.execute(trial_function(name, reverse=True))
    op.execute(previous("EXPIRES_TRIGGER", "0039_signups.py"))
    op.execute(fixture_refresh(live_function("sandbox_reattest"), reverse=True))
    for table in ("resources", "resource_facts", "incidents"):
        op.execute(f"ALTER TABLE execbound.{table} DROP COLUMN IF EXISTS demo_fixture")
    op.execute("ALTER TABLE execbound.onboarding_slots DROP COLUMN community_at")
    op.execute("ALTER TABLE execbound.onboarding_slots FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security=on")
