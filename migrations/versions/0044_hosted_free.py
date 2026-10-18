"""Hosted Free (#439): the plan, the cap, the fallback and dormancy.

`tenants.plan` defaults to `team`, which means no platform cap, so no tenant acquires a cap
by existing and the migration needs no backfill. `admin_create_principal` is dropped and
recreated with the cap check, because it is the only way a tenant can create an agent
principal itself; the owner CLI's `principal-create` (`administration.create_principal`)
inserts one directly and is not reachable from any tenant-facing surface, a documented
operator override of the cap rather than a defect this migration's check needs to close. It
is recreated in the three-argument form `0041_spaces` left it in, with spaces' body kept
exactly and the cap added immediately before the `INSERT`, so an invalid or archived space
is reported before entitlement is evaluated. The cap counts by tenant alone and never by
`p_space`: a space is a view, not an allowance. The limit itself is not read from a table:
it is hard-coded into this function's own text as a `CASE` over `t.plan`, matching
`execbound.plans.PLANS` by construction. A reference table with no `tenant_id` cannot
satisfy `check_runtime`'s forced-row-level-security invariant (`src/execbound/db.py`), so
the two stay two hard-coded copies on purpose; `test_hf12_the_limits_agree` in
`tests/test_hosted_free.py` is what proves they agree.

`principals.dormant_at` is distinct from 0036's `deactivated_at`: a sleeping agent is kept
and therefore counted, a deactivated one is not. The two columns are never both set.
`admin_reactivate_principal` is recreated so that waking clears `dormant_at`, and so that
reactivating an agent a person deactivated by hand, which takes back the allowance the
deactivation freed, is refused with `PLAN_LIMIT` at the cap under the same tenant-row lock
the creation check takes. Waking a sleeping agent skips that check, because a sleeping agent
never stopped counting.
"""

from alembic import op
from sqlalchemy import text

revision = "0044_hosted_free"
down_revision = "0043_directory_sign_in"
branch_labels = None
depends_on = None

# The 0021 preamble, restated exactly as 0036 restates it: the tenant comes from the fence
# setting; the actor must be an active ADMIN of that active tenant.
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

# 0036's own target check, restated: a person who may be reactivated is a principal of the
# tenant that is not an administrator and is not the actor.
TARGET_CHECK = """
    IF p_principal IS NULL OR p_principal = p_actor OR NOT EXISTS (
        SELECT 1 FROM execbound.principals p
        WHERE p.tenant_id = v_tenant AND p.principal_id = p_principal AND p.kind <> 'ADMIN'
    ) THEN
        RAISE EXCEPTION 'INVALID_PRINCIPAL';
    END IF;
"""

# `0041_spaces`' body, restored verbatim by downgrade(): the three-argument form, with a
# space and no cap. Copied byte for byte from that migration's `CREATE_PRINCIPAL`, not
# 0021's two-argument body, because it is still the body at `0043_directory_sign_in`, the
# revision this one downgrades to.
CREATE_PRINCIPAL_ORIGINAL = """
CREATE FUNCTION execbound.admin_create_principal(
    p_actor uuid, p_kind text, p_space uuid)
RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_principal uuid := gen_random_uuid();
BEGIN
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
    IF p_kind IS NULL OR p_kind NOT IN ('AGENT', 'HUMAN_APPROVER') THEN
        RAISE EXCEPTION 'INVALID_KIND';
    END IF;
    -- An agent is owned by one space, so it must be given one. A person is a member of
    -- spaces rather than owned by one, and naming a space for them seats them in it with
    -- the role their kind allows, which is exactly what this migration does for every
    -- approver that already existed.
    IF p_kind = 'AGENT' AND p_space IS NULL THEN
        RAISE EXCEPTION 'INVALID_SPACE';
    END IF;
    IF p_space IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM execbound.spaces s
            WHERE s.tenant_id = v_tenant AND s.space_id = p_space
        ) THEN
            RAISE EXCEPTION 'INVALID_SPACE';
        END IF;
        IF EXISTS (
            SELECT 1 FROM execbound.spaces s
            WHERE s.tenant_id = v_tenant AND s.space_id = p_space
              AND s.archived_at IS NOT NULL
        ) THEN
            RAISE EXCEPTION 'SPACE_ARCHIVED';
        END IF;
        -- An administrator who is a member of spaces creates agents and seats people
        -- in those spaces only.
        IF EXISTS (
            SELECT 1 FROM execbound.space_members m
            WHERE m.tenant_id = v_tenant AND m.principal_id = p_actor
        ) AND NOT EXISTS (
            SELECT 1 FROM execbound.space_members m
            WHERE m.tenant_id = v_tenant AND m.principal_id = p_actor
              AND m.space_id = p_space AND m.role = 'ADMIN'
        ) THEN
            RAISE EXCEPTION 'INVALID_SPACE';
        END IF;
    END IF;
    INSERT INTO execbound.principals (tenant_id, principal_id, kind, space_id)
    VALUES (v_tenant, v_principal, p_kind,
            CASE WHEN p_kind = 'AGENT' THEN p_space END);
    IF p_kind = 'HUMAN_APPROVER' AND p_space IS NOT NULL THEN
        INSERT INTO execbound.space_members
            (tenant_id, space_id, principal_id, role, assigned_at)
        VALUES (v_tenant, p_space, v_principal, 'HUMAN_APPROVER', now());
    END IF;
    RETURN v_principal;
END $$
"""

# Spaces' body exactly, plus the cap. The cap counts an agent that is live or asleep and
# skips one a person switched off by hand. A plan with no limit (every plan but `free`)
# is uncapped and costs one extra CASE branch. The literal `3` here is
# `execbound.plans.PLANS['free'].agent_principals`, hard-coded rather than read from a
# table: a `SECURITY DEFINER` function cannot import Python, and a global reference
# table has no `tenant_id` to satisfy forced row-level security.
# `test_hf12_the_limits_agree` proves the two never drift apart.
CREATE_PRINCIPAL = """
CREATE FUNCTION execbound.admin_create_principal(
    p_actor uuid, p_kind text, p_space uuid)
RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_principal uuid := gen_random_uuid();
    v_limit integer;
    v_held integer;
BEGIN
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
    IF p_kind IS NULL OR p_kind NOT IN ('AGENT', 'HUMAN_APPROVER') THEN
        RAISE EXCEPTION 'INVALID_KIND';
    END IF;
    -- An agent is owned by one space, so it must be given one. A person is a member of
    -- spaces rather than owned by one, and naming a space for them seats them in it with
    -- the role their kind allows, as `0041_spaces` did for every approver that already
    -- existed when it ran.
    IF p_kind = 'AGENT' AND p_space IS NULL THEN
        RAISE EXCEPTION 'INVALID_SPACE';
    END IF;
    IF p_space IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM execbound.spaces s
            WHERE s.tenant_id = v_tenant AND s.space_id = p_space
        ) THEN
            RAISE EXCEPTION 'INVALID_SPACE';
        END IF;
        IF EXISTS (
            SELECT 1 FROM execbound.spaces s
            WHERE s.tenant_id = v_tenant AND s.space_id = p_space
              AND s.archived_at IS NOT NULL
        ) THEN
            RAISE EXCEPTION 'SPACE_ARCHIVED';
        END IF;
        -- An administrator who is a member of spaces creates agents and seats people
        -- in those spaces only.
        IF EXISTS (
            SELECT 1 FROM execbound.space_members m
            WHERE m.tenant_id = v_tenant AND m.principal_id = p_actor
        ) AND NOT EXISTS (
            SELECT 1 FROM execbound.space_members m
            WHERE m.tenant_id = v_tenant AND m.principal_id = p_actor
              AND m.space_id = p_space AND m.role = 'ADMIN'
        ) THEN
            RAISE EXCEPTION 'INVALID_SPACE';
        END IF;
    END IF;
    -- The cap, after every one of spaces' validations and immediately before the INSERT,
    -- so an invalid or archived space is reported as such before entitlement is evaluated.
    IF p_kind = 'AGENT' THEN
        -- FOR NO KEY UPDATE serializes two concurrent cap checks on the same tenant
        -- against each other (it conflicts with itself), without blocking the FOR KEY
        -- SHARE another table's FK insert takes against this same row. Without it, two
        -- sessions under READ COMMITTED can both read the same v_held and both insert,
        -- overshooting the cap; see tests/test_hosted_free.py::test_hf9.
        SELECT CASE t.plan WHEN 'free' THEN 3 ELSE NULL END INTO v_limit
          FROM execbound.tenants t WHERE t.tenant_id = v_tenant FOR NO KEY UPDATE;
        IF v_limit IS NOT NULL THEN
            -- Counted by tenant alone and never filtered by p_space: a space is a view,
            -- not an allowance, so three agents is three however they are divided.
            SELECT count(*) INTO v_held FROM execbound.principals p
             WHERE p.tenant_id = v_tenant AND p.kind = 'AGENT'
               AND (p.active OR p.dormant_at IS NOT NULL);
            IF v_held >= v_limit THEN
                RAISE EXCEPTION 'PLAN_LIMIT';
            END IF;
        END IF;
    END IF;
    INSERT INTO execbound.principals (tenant_id, principal_id, kind, space_id)
    VALUES (v_tenant, v_principal, p_kind,
            CASE WHEN p_kind = 'AGENT' THEN p_space END);
    IF p_kind = 'HUMAN_APPROVER' AND p_space IS NOT NULL THEN
        INSERT INTO execbound.space_members
            (tenant_id, space_id, principal_id, role, assigned_at)
        VALUES (v_tenant, p_space, v_principal, 'HUMAN_APPROVER', now());
    END IF;
    RETURN v_principal;
END $$
"""

# Day fourteen. The same guards as `sandbox_expire`, and the opposite outcome: the tenant
# stays active and only its plan changes. A fallen-back slot is no longer a sandbox.
FALLBACK = """
CREATE FUNCTION execbound.sandbox_fallback(p_now timestamptz)
RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_slot execbound.onboarding_slots%ROWTYPE;
    v_actor uuid;
BEGIN
    IF v_tenant IS NULL THEN
        RAISE EXCEPTION 'INVALID_SLOT';
    END IF;
    IF p_now IS NULL OR abs(extract(epoch FROM (p_now - now()))) > 300 THEN
        RAISE EXCEPTION 'INVALID_CLOCK';
    END IF;
    SELECT * INTO v_slot FROM execbound.onboarding_slots s
     WHERE s.tenant_id = v_tenant FOR UPDATE;
    IF NOT FOUND OR v_slot.claimed_at IS NULL OR v_slot.converted_at IS NOT NULL
       OR v_slot.deactivated_at IS NOT NULL OR v_slot.fell_back_at IS NOT NULL
       OR coalesce(v_slot.extended_until, v_slot.expires_at) > p_now THEN
        RAISE EXCEPTION 'INVALID_SLOT';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM execbound.tenants t WHERE t.tenant_id = v_tenant AND t.active
    ) THEN
        RAISE EXCEPTION 'INVALID_SLOT';
    END IF;
    SELECT p.principal_id INTO v_actor FROM execbound.principals p
     WHERE p.tenant_id = v_tenant AND p.kind = 'ADMIN' AND p.active
     ORDER BY p.principal_id LIMIT 1;
    IF v_actor IS NULL THEN
        RAISE EXCEPTION 'INVALID_ACTOR';
    END IF;
    UPDATE execbound.tenants SET plan = 'free' WHERE tenant_id = v_tenant;
    UPDATE execbound.onboarding_slots SET fell_back_at = p_now WHERE tenant_id = v_tenant;
    RETURN v_actor;
END $$
"""

# Dormancy. Principals only: an inactive tenant refuses sessions, and waking would be
# unreachable. Refuses a tenant that is not free, and one with a recent governed request.
# Silence is measured from the later of the slot's own `claimed_at` and the last governed
# request (review ruling D on Task 5): reading only `max(occurred_at)` made a tenant with no
# `execution.*` event at all due the instant it fell back, sleeping it in the very sweep that
# made it free. An unclaimed slot (`v_claimed IS NULL`) cannot be free at all under decision
# 1, but is refused defensively rather than treated as infinitely silent.
SLEEP = """
CREATE FUNCTION execbound.agents_sleep(p_now timestamptz)
RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_actor uuid;
    v_claimed timestamptz;
    v_last timestamptz;
    v_silent_since timestamptz;
BEGIN
    IF v_tenant IS NULL THEN
        RAISE EXCEPTION 'INVALID_TENANT';
    END IF;
    IF p_now IS NULL OR abs(extract(epoch FROM (p_now - now()))) > 300 THEN
        RAISE EXCEPTION 'INVALID_CLOCK';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM execbound.tenants t
         WHERE t.tenant_id = v_tenant AND t.active AND t.plan = 'free'
    ) THEN
        RAISE EXCEPTION 'INVALID_PLAN';
    END IF;
    SELECT s.claimed_at INTO v_claimed FROM execbound.onboarding_slots s
     WHERE s.tenant_id = v_tenant;
    IF v_claimed IS NULL THEN
        RAISE EXCEPTION 'INVALID_STATE';
    END IF;
    SELECT max(e.occurred_at) INTO v_last FROM execbound.audit_events e
     WHERE e.tenant_id = v_tenant AND e.kind LIKE 'execution.%';
    v_silent_since := greatest(v_claimed, coalesce(v_last, v_claimed));
    IF v_silent_since > p_now - interval '90 days' THEN
        RAISE EXCEPTION 'INVALID_STATE';
    END IF;
    SELECT p.principal_id INTO v_actor FROM execbound.principals p
     WHERE p.tenant_id = v_tenant AND p.kind = 'ADMIN' AND p.active
     ORDER BY p.principal_id LIMIT 1;
    IF v_actor IS NULL THEN
        RAISE EXCEPTION 'INVALID_ACTOR';
    END IF;
    UPDATE execbound.principals
       SET active = false, dormant_at = p_now
     WHERE tenant_id = v_tenant AND kind = 'AGENT' AND active
       AND deactivated_at IS NULL;
    RETURN v_actor;
END $$
"""

# 0039's original body, restored verbatim by downgrade(): no `fell_back_at` guard.
EXPIRE_ORIGINAL = r"""
CREATE OR REPLACE FUNCTION execbound.sandbox_expire(p_reason text, p_now timestamptz)
RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_slot execbound.onboarding_slots%ROWTYPE;
    v_actor uuid;
BEGIN
    IF v_tenant IS NULL OR p_reason IS NULL OR p_reason !~ '^[a-z][a-z0-9_]{0,39}$' THEN
        RAISE EXCEPTION 'INVALID_SLOT';
    END IF;
    IF p_now IS NULL OR abs(extract(epoch FROM (p_now - now()))) > 300 THEN
        RAISE EXCEPTION 'INVALID_CLOCK';
    END IF;
    SELECT * INTO v_slot FROM execbound.onboarding_slots s
     WHERE s.tenant_id = v_tenant FOR UPDATE;
    IF NOT FOUND OR v_slot.claimed_at IS NULL OR v_slot.converted_at IS NOT NULL
       OR v_slot.deactivated_at IS NOT NULL
       OR coalesce(v_slot.extended_until, v_slot.expires_at) > p_now THEN
        RAISE EXCEPTION 'INVALID_SLOT';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM execbound.tenants t WHERE t.tenant_id = v_tenant AND t.active
    ) THEN
        RAISE EXCEPTION 'INVALID_SLOT';
    END IF;
    SELECT p.principal_id INTO v_actor FROM execbound.principals p
     WHERE p.tenant_id = v_tenant AND p.kind = 'ADMIN' AND p.active
     ORDER BY p.principal_id LIMIT 1;
    IF v_actor IS NULL THEN
        RAISE EXCEPTION 'INVALID_ACTOR';
    END IF;
    UPDATE execbound.tenants SET active = false WHERE tenant_id = v_tenant;
    UPDATE execbound.onboarding_slots SET deactivated_at = p_now WHERE tenant_id = v_tenant;
    RETURN v_actor;
END $$
"""

# `sandbox_expire`, recreated with one added clause: a fallen-back slot is no longer a
# sandbox and is refused here exactly as it already was by `sandbox_fallback`. Decision 4 in
# the spec requires the two to be mutually exclusive in both orders; before this, only the
# fallback-refuses-an-already-expired-slot direction held.
EXPIRE = r"""
CREATE OR REPLACE FUNCTION execbound.sandbox_expire(p_reason text, p_now timestamptz)
RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_slot execbound.onboarding_slots%ROWTYPE;
    v_actor uuid;
BEGIN
    IF v_tenant IS NULL OR p_reason IS NULL OR p_reason !~ '^[a-z][a-z0-9_]{0,39}$' THEN
        RAISE EXCEPTION 'INVALID_SLOT';
    END IF;
    IF p_now IS NULL OR abs(extract(epoch FROM (p_now - now()))) > 300 THEN
        RAISE EXCEPTION 'INVALID_CLOCK';
    END IF;
    SELECT * INTO v_slot FROM execbound.onboarding_slots s
     WHERE s.tenant_id = v_tenant FOR UPDATE;
    IF NOT FOUND OR v_slot.claimed_at IS NULL OR v_slot.converted_at IS NOT NULL
       OR v_slot.deactivated_at IS NOT NULL OR v_slot.fell_back_at IS NOT NULL
       OR coalesce(v_slot.extended_until, v_slot.expires_at) > p_now THEN
        RAISE EXCEPTION 'INVALID_SLOT';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM execbound.tenants t WHERE t.tenant_id = v_tenant AND t.active
    ) THEN
        RAISE EXCEPTION 'INVALID_SLOT';
    END IF;
    SELECT p.principal_id INTO v_actor FROM execbound.principals p
     WHERE p.tenant_id = v_tenant AND p.kind = 'ADMIN' AND p.active
     ORDER BY p.principal_id LIMIT 1;
    IF v_actor IS NULL THEN
        RAISE EXCEPTION 'INVALID_ACTOR';
    END IF;
    UPDATE execbound.tenants SET active = false WHERE tenant_id = v_tenant;
    UPDATE execbound.onboarding_slots SET deactivated_at = p_now WHERE tenant_id = v_tenant;
    RETURN v_actor;
END $$
"""

# 0039's original body, restored verbatim by downgrade(): no `fell_back_at` guard.
NOTICE_ORIGINAL = r"""
CREATE OR REPLACE FUNCTION execbound.sandbox_notice(p_now timestamptz)
RETURNS timestamptz
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_slot execbound.onboarding_slots%ROWTYPE;
    v_end timestamptz;
BEGIN
    IF v_tenant IS NULL THEN
        RAISE EXCEPTION 'INVALID_SLOT';
    END IF;
    IF p_now IS NULL OR abs(extract(epoch FROM (p_now - now()))) > 300 THEN
        RAISE EXCEPTION 'INVALID_CLOCK';
    END IF;
    SELECT * INTO v_slot FROM execbound.onboarding_slots s
     WHERE s.tenant_id = v_tenant FOR UPDATE;
    IF NOT FOUND OR v_slot.claimed_at IS NULL OR v_slot.converted_at IS NOT NULL
       OR v_slot.deactivated_at IS NOT NULL OR v_slot.notice_at IS NOT NULL THEN
        RAISE EXCEPTION 'INVALID_SLOT';
    END IF;
    v_end := coalesce(v_slot.extended_until, v_slot.expires_at);
    IF v_end IS NULL OR v_end <= p_now OR v_end - p_now > interval '3 days' THEN
        RAISE EXCEPTION 'INVALID_STATE';
    END IF;
    UPDATE execbound.onboarding_slots SET notice_at = p_now WHERE tenant_id = v_tenant;
    RETURN v_end;
END $$
"""

# `sandbox_notice`, recreated with the same added clause: a fallen-back slot no longer warns
# about an ending that will not happen.
NOTICE = r"""
CREATE OR REPLACE FUNCTION execbound.sandbox_notice(p_now timestamptz)
RETURNS timestamptz
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_slot execbound.onboarding_slots%ROWTYPE;
    v_end timestamptz;
BEGIN
    IF v_tenant IS NULL THEN
        RAISE EXCEPTION 'INVALID_SLOT';
    END IF;
    IF p_now IS NULL OR abs(extract(epoch FROM (p_now - now()))) > 300 THEN
        RAISE EXCEPTION 'INVALID_CLOCK';
    END IF;
    SELECT * INTO v_slot FROM execbound.onboarding_slots s
     WHERE s.tenant_id = v_tenant FOR UPDATE;
    IF NOT FOUND OR v_slot.claimed_at IS NULL OR v_slot.converted_at IS NOT NULL
       OR v_slot.deactivated_at IS NOT NULL OR v_slot.notice_at IS NOT NULL
       OR v_slot.fell_back_at IS NOT NULL THEN
        RAISE EXCEPTION 'INVALID_SLOT';
    END IF;
    v_end := coalesce(v_slot.extended_until, v_slot.expires_at);
    IF v_end IS NULL OR v_end <= p_now OR v_end - p_now > interval '3 days' THEN
        RAISE EXCEPTION 'INVALID_STATE';
    END IF;
    UPDATE execbound.onboarding_slots SET notice_at = p_now WHERE tenant_id = v_tenant;
    RETURN v_end;
END $$
"""

# 0036's original body, restored verbatim by downgrade(): waking clears only `deactivated_at`.
REACTIVATE_ORIGINAL = f"""
CREATE OR REPLACE FUNCTION execbound.admin_reactivate_principal(p_actor uuid, p_principal uuid)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
BEGIN
    {ACTOR_CHECK}
    {TARGET_CHECK}
    UPDATE execbound.principals SET active = true, deactivated_at = NULL
    WHERE tenant_id = v_tenant AND principal_id = p_principal AND NOT active;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'INVALID_STATE';
    END IF;
END $$
"""

# Waking clears whichever marker put the principal to sleep. Reactivating a dormant agent
# through the same path a hand-deactivated one uses keeps there being exactly one "turn it
# back on" command; the design names this `admin_reactivate_principal` plus one owner
# command that calls it for every sleeping agent in a tenant.
#
# Reactivating an agent a person deactivated by hand is a creation for the cap's purposes
# (decision 5, corrected in the final review): the deactivation freed its allowance, so
# taking the allowance back is refused with `PLAN_LIMIT` when the tenant is at its cap.
# Without this, a tenant at three could deactivate one, create another and reactivate the
# first, holding four, and repeat without limit. The check takes the same `FOR NO KEY
# UPDATE` on the tenant row `admin_create_principal` takes, counts the same rows and
# compares against the same `CASE`, so a creation and a reactivation contending for the
# last allowance serialize on one lock and exactly one wins (`test_hf58` in
# `tests/test_hosted_free.py`). Waking a sleeping agent is not a creation, because a
# sleeping agent never stopped counting, so a dormant target skips the check entirely. The
# target's own row is locked first, so whether it is deactivated or asleep cannot change
# between the decision read here and the `UPDATE` that acts on it; a concurrent
# reactivation of the same agent then finds it active and gets `INVALID_STATE`, never a
# misleading `PLAN_LIMIT`.
REACTIVATE = f"""
CREATE OR REPLACE FUNCTION execbound.admin_reactivate_principal(p_actor uuid, p_principal uuid)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_kind text;
    v_deactivated timestamptz;
    v_limit integer;
    v_held integer;
BEGIN
    {ACTOR_CHECK}
    {TARGET_CHECK}
    SELECT p.kind, p.deactivated_at INTO v_kind, v_deactivated
      FROM execbound.principals p
     WHERE p.tenant_id = v_tenant AND p.principal_id = p_principal
       FOR NO KEY UPDATE;
    IF v_kind = 'AGENT' AND v_deactivated IS NOT NULL THEN
        SELECT CASE t.plan WHEN 'free' THEN 3 ELSE NULL END INTO v_limit
          FROM execbound.tenants t WHERE t.tenant_id = v_tenant FOR NO KEY UPDATE;
        IF v_limit IS NOT NULL THEN
            SELECT count(*) INTO v_held FROM execbound.principals p
             WHERE p.tenant_id = v_tenant AND p.kind = 'AGENT'
               AND (p.active OR p.dormant_at IS NOT NULL);
            IF v_held >= v_limit THEN
                RAISE EXCEPTION 'PLAN_LIMIT';
            END IF;
        END IF;
    END IF;
    UPDATE execbound.principals SET active = true, deactivated_at = NULL, dormant_at = NULL
    WHERE tenant_id = v_tenant AND principal_id = p_principal AND NOT active;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'INVALID_STATE';
    END IF;
END $$
"""

# 0029's original body, restored verbatim by downgrade(): claiming a slot stamps no plan.
ONBOARDING_CLAIM_ORIGINAL = r"""
CREATE OR REPLACE FUNCTION execbound.onboarding_claim(
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
    UPDATE execbound.onboarding_invitations SET redeemed_at = now()
     WHERE tenant_id = v_tenant AND invitation_id = p_invitation;
    UPDATE execbound.onboarding_slots SET claimed_at = now() WHERE tenant_id = v_tenant;
    RETURN v_tenant;
END $$
"""

# `onboarding_claim` stamps the plan, so `sandbox` is reachable and a report tells a running
# trial from a customer without joining to the slots table. Otherwise unchanged from 0029.
ONBOARDING_CLAIM = r"""
CREATE OR REPLACE FUNCTION execbound.onboarding_claim(
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
        UPDATE execbound.tenants SET name = v_name, active = true, plan = 'sandbox'
         WHERE tenant_id = v_tenant;
    EXCEPTION WHEN unique_violation THEN
        RAISE EXCEPTION 'NAME_TAKEN';
    END;
    INSERT INTO execbound.principals (tenant_id, principal_id, kind)
    VALUES (v_tenant, p_admin, 'ADMIN');
    INSERT INTO execbound.credentials
        (tenant_id, credential_id, principal_id, token_hash, issued_at, expires_at)
    VALUES (v_tenant, p_credential, p_admin, p_credential_hash, p_issued_at, p_expires_at);
    UPDATE execbound.onboarding_invitations SET redeemed_at = now()
     WHERE tenant_id = v_tenant AND invitation_id = p_invitation;
    UPDATE execbound.onboarding_slots SET claimed_at = now() WHERE tenant_id = v_tenant;
    RETURN v_tenant;
END $$
"""


def _role_exists(role: str) -> bool:
    return bool(
        op.get_bind()
        .execute(text("SELECT 1 FROM pg_roles WHERE rolname = :role"), {"role": role})
        .scalar()
    )


def _grant(signature: str) -> None:
    op.execute(f"REVOKE ALL ON FUNCTION execbound.{signature} FROM PUBLIC")
    for role in ("anon", "authenticated", "service_role"):
        if _role_exists(role):
            op.execute(f"REVOKE ALL ON FUNCTION execbound.{signature} FROM {role}")
    op.execute(f"GRANT EXECUTE ON FUNCTION execbound.{signature} TO execbound_app")


def upgrade() -> None:
    op.execute(
        "ALTER TABLE execbound.tenants ADD COLUMN plan text NOT NULL DEFAULT 'team' "
        "CHECK (plan IN ('sandbox', 'free', 'team'))"
    )
    op.execute("ALTER TABLE execbound.onboarding_slots ADD COLUMN fell_back_at timestamptz")
    op.execute(
        "ALTER TABLE execbound.onboarding_slots ADD CONSTRAINT onboarding_slots_one_ending "
        "CHECK (fell_back_at IS NULL OR converted_at IS NULL)"
    )
    op.execute("ALTER TABLE execbound.principals ADD COLUMN dormant_at timestamptz")
    op.execute(
        "ALTER TABLE execbound.principals ADD CONSTRAINT principals_one_off_switch "
        "CHECK (dormant_at IS NULL OR deactivated_at IS NULL)"
    )
    # The same invariant 0036 gave `deactivated_at`: a marker that puts a principal to sleep
    # is never set on one that is still active. Nothing on this migration's own paths can
    # produce "active and dormant", but Tasks 4 and 5 both write this column.
    op.execute(
        "ALTER TABLE execbound.principals ADD CONSTRAINT principals_dormant_requires_inactive "
        "CHECK (dormant_at IS NULL OR NOT active)"
    )
    # A plan with no cap (every plan but `free`) is the ordinary case and costs one index
    # scan; the partial index carries only the rows a capped tenant's count has to see.
    op.execute(
        "CREATE INDEX principals_tenant_agent_held ON execbound.principals (tenant_id) "
        "WHERE kind = 'AGENT' AND (active OR dormant_at IS NOT NULL)"
    )
    op.execute("DROP FUNCTION execbound.admin_create_principal(uuid, text, uuid)")
    op.execute(CREATE_PRINCIPAL)
    _grant("admin_create_principal(uuid, text, uuid)")
    op.execute(FALLBACK)
    _grant("sandbox_fallback(timestamptz)")
    op.execute(SLEEP)
    _grant("agents_sleep(timestamptz)")
    # Same signatures as 0036 and 0029: `CREATE OR REPLACE` keeps their existing grants.
    op.execute(REACTIVATE)
    op.execute(ONBOARDING_CLAIM)
    # Same signatures as 0039: `CREATE OR REPLACE` keeps their existing grants too.
    op.execute(EXPIRE)
    op.execute(NOTICE)


def downgrade() -> None:
    op.execute("DROP FUNCTION execbound.agents_sleep(timestamptz)")
    op.execute("DROP FUNCTION execbound.sandbox_fallback(timestamptz)")
    op.execute("DROP FUNCTION execbound.admin_create_principal(uuid, text, uuid)")
    op.execute(CREATE_PRINCIPAL_ORIGINAL)
    _grant("admin_create_principal(uuid, text, uuid)")
    op.execute(REACTIVATE_ORIGINAL)
    op.execute(ONBOARDING_CLAIM_ORIGINAL)
    op.execute(EXPIRE_ORIGINAL)
    op.execute(NOTICE_ORIGINAL)
    op.execute("DROP INDEX execbound.principals_tenant_agent_held")
    op.execute(
        "ALTER TABLE execbound.principals DROP CONSTRAINT principals_dormant_requires_inactive"
    )
    op.execute("ALTER TABLE execbound.principals DROP CONSTRAINT principals_one_off_switch")
    op.execute("ALTER TABLE execbound.principals DROP COLUMN dormant_at")
    op.execute("ALTER TABLE execbound.onboarding_slots DROP CONSTRAINT onboarding_slots_one_ending")
    op.execute("ALTER TABLE execbound.onboarding_slots DROP COLUMN fell_back_at")
    op.execute("ALTER TABLE execbound.tenants DROP COLUMN plan")
