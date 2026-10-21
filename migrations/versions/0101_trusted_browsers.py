# SPDX-License-Identifier: AGPL-3.0-only
"""A person may trust a browser for thirty days, so signing in on it skips the second factor (#859).

`trusted_browsers` holds an account's trusts, account-scoped like `user_passkeys`: forced row
level security under the `account_isolation` fence, SELECT for the runtime and nothing else,
and every write through the definer functions below. A row keeps the SHA-256 of the cookie's
secret and never the secret, the account and factor versions it was granted at, when and by
which factor the person verified, the device label, and when it was created, expires (thirty
days on), was last used and was removed.

* `trusted_browser_add` grants a trust from a session that holds a recent verification of its
  own: an assurance at the account's enabled factor version, by a real factor (never
  `trusted`), within the step-up's thirty minutes. The trust records that assurance's own
  `verified_at` and method. It reads the session's account, the account version and the
  factor version itself, refuses where the workspace forbids trust, and revokes the oldest live
  trusts beyond ten.
* `trusted_browser_use` writes a pending session's `session_assurance` with method `trusted`
  and the trust's original `verified_at`, never now, when the hash matches a live trust of the
  session's account at the current account and factor versions in a workspace that allows
  trust, and records `last_used_at`. In the same statement it rotates the session's token and
  CSRF digests to the ones the caller minted, as `rotate_session` does after a verification,
  so the token the sign-in was issued under no longer loads. It answers whether it did. So the
  sign-in factor is satisfied while the thirty-minute step-up, the database's `fresh` and the
  switch carry still read the age of the real verification.
* `trusted_browser_remove` and `trusted_browser_remove_all` remove trusts of the account the
  transaction is in.
* `trusted_browser_policy` sets the workspace's `allow_trusted_browsers`, for a workspace
  administrator alone (`INVALID_IDENTITY` otherwise), recording who and when as the
  requirement's own writer does.
* `account_sign_out_others` is "Sign out other devices" for a session with no account sign-in
  whose membership links an account: it moves the account's version, as the account path's
  `account_session_revoke` does, so every trust ends there too; the acting session is brought
  to the new version and every account sign-in of the account ends.

Adding and removing record `trusted_browser_added` and `trusted_browser_removed` in
`user_security_events`, whose kind has no list to widen (only a length check); a use records
nothing there, and the runtime appends `account_security.trusted_sign_in` to the workspace's
audit chain in the transaction that called `trusted_browser_use`. `session_assurance.method`
admits `trusted`, and `account_security_policy` gains `allow_trusted_browsers`, true by
default. Every function takes the time as `p_now`, owns its
`search_path`, and is executable by the runtime role alone: PUBLIC and the Supabase platform
roles hold nothing on it.

Method `trusted` is never a fresh verification, whatever its age: the `fresh` read of
`account_security_change` and `user_security_change` (the thirty minutes of
`0067_step_up_window`) and `account_switch`'s carry (`0089_assurance_carry`) refuse it. A trust
used within thirty minutes of its own verification therefore neither passes a step-up nor
carries into another workspace, which may forbid trust. The three are patched in place, as
`0100_longer_sessions` patches its four: the live definition is read, each fragment must occur
in it exactly once, and `CREATE OR REPLACE` keeps the owner, `SECURITY DEFINER`, the
`search_path` and the grants.

The downgrade restores the three definitions, drops the functions, deletes every `trusted`
assurance (row level security lifted around that one statement, as `0100_longer_sessions` does,
so every tenant's rows are reached), so a session signed in through trust owes its factor
again, restores the method check, and drops the column and the table. The security events
stay, as records.
"""

from alembic import op
from sqlalchemy import text

revision = "0101_trusted_browsers"
down_revision = "0100_longer_sessions"
branch_labels = None
depends_on = None

SUPABASE_ROLES = ("anon", "authenticated", "service_role")
ACCOUNT = "nullif((SELECT current_setting('execbound.account_id',true)),'')::uuid"
METHODS = "'totp','recovery','passkey'"

# The session behind a grant or a use: live, with a live credential of an active principal of
# its kind, as `user_security_change` reads it, and its account, either the one it signed in
# as or, for a session issued before account sign-in, the one its membership links. The
# account must be active at the version the session was issued under. Sets `s`, `v_account`
# and `u`, and enters the account's row security.
SESSION = """
    IF t IS NULL OR p_tenant IS DISTINCT FROM t THEN RAISE EXCEPTION 'INVALID_TENANT'; END IF;
    IF p_now IS NULL THEN RAISE EXCEPTION 'INVALID_SESSION'; END IF;
    SELECT * INTO s FROM execbound.human_sessions WHERE tenant_id=t AND session_id=p_session;
    IF s.session_id IS NULL OR s.revoked_at IS NOT NULL OR p_now<s.created_at
        OR p_now>=s.expires_at OR NOT EXISTS(
          SELECT 1 FROM execbound.credentials c JOIN execbound.principals p
              USING(tenant_id,principal_id)
          WHERE c.tenant_id=t AND c.credential_id=s.credential_id AND p.active
            AND c.revoked_at IS NULL AND c.expires_at>p_now AND p.kind=s.kind
        ) THEN RAISE EXCEPTION 'INVALID_SESSION'; END IF;
    v_account := s.account_id;
    IF v_account IS NULL THEN
        SELECT m.account_id INTO v_account FROM execbound.workspace_memberships m
            WHERE m.tenant_id=t AND m.principal_id=s.principal_id AND m.active
            AND m.version=s.membership_version;
        IF v_account IS NULL THEN RAISE EXCEPTION 'ACCOUNT_SIGN_IN_REQUIRED'; END IF;
    END IF;
    PERFORM set_config('execbound.account_id',v_account::text,true);
    SELECT * INTO u FROM execbound.user_accounts WHERE account_id=v_account FOR UPDATE;
    IF u.account_id IS NULL OR NOT u.active
        OR (s.account_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM execbound.account_sessions x
            WHERE x.account_id=v_account AND x.session_id=s.account_session_id
            AND x.version=u.version AND x.revoked_at IS NULL AND x.created_at<=p_now
            AND x.expires_at>p_now AND x.current_session=p_session AND x.current_tenant=t))
        OR (s.account_id IS NULL AND s.account_version IS DISTINCT FROM u.version)
        THEN RAISE EXCEPTION 'INVALID_SESSION'; END IF;
    SELECT * INTO f FROM execbound.user_factors WHERE account_id=v_account;
"""

# A live trust: not removed, not expired, and granted at the account's current version and
# its enabled factor's current version. `u` and `f` are the account and factor rows.
LIVE = (
    "b.revoked_at IS NULL AND b.created_at<=p_now AND b.expires_at>p_now "
    "AND b.account_version=u.version AND f.enabled_at IS NOT NULL "
    "AND b.factor_version=f.version"
)

ADD = f"""
CREATE FUNCTION execbound.trusted_browser_add(p_tenant uuid, p_session uuid, p_browser uuid,
    p_hash text, p_label text, p_method text, p_verified_at timestamptz, p_now timestamptz)
RETURNS timestamptz
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    t uuid := nullif(current_setting('execbound.tenant_id',true),'')::uuid;
    s execbound.human_sessions; v_account uuid; u execbound.user_accounts;
    f execbound.user_factors; a execbound.session_assurance; v_expires timestamptz;
BEGIN
{SESSION}
    -- Trust records the verification this session holds itself: a real factor, at the
    -- enabled factor's current version, within the step-up's thirty minutes. The caller's
    -- view of it must agree; what is stored is the database's own.
    SELECT * INTO a FROM execbound.session_assurance WHERE tenant_id=t AND session_id=p_session;
    IF f.enabled_at IS NULL OR a.session_id IS NULL OR a.version<>f.version
        OR a.method NOT IN ({METHODS}) OR a.method IS DISTINCT FROM p_method
        OR a.verified_at>p_now OR a.verified_at<=p_now-interval '30 minutes'
        OR p_verified_at IS NULL OR p_verified_at<a.verified_at OR p_verified_at>p_now
        THEN RAISE EXCEPTION 'RECENT_AUTH_REQUIRED'; END IF;
    IF EXISTS(SELECT 1 FROM execbound.account_security_policy p WHERE p.tenant_id=t
        AND NOT p.allow_trusted_browsers) THEN RAISE EXCEPTION 'TRUST_NOT_ALLOWED'; END IF;
    v_expires := p_now+interval '30 days';
    INSERT INTO execbound.trusted_browsers(account_id,browser_id,token_hash,account_version,
        factor_version,verified_at,method,label,created_at,expires_at)
        VALUES(v_account,p_browser,p_hash,u.version,f.version,a.verified_at,a.method,p_label,
            p_now,v_expires);
    INSERT INTO execbound.user_security_events(account_id,kind,occurred_at)
        VALUES(v_account,'trusted_browser_added',p_now);
    -- At most ten live trusts: the oldest beyond them are removed, never the one just added.
    WITH removed AS (
        UPDATE execbound.trusted_browsers SET revoked_at=p_now
        WHERE account_id=v_account AND browser_id IN (
            SELECT b.browser_id FROM execbound.trusted_browsers b
            WHERE b.account_id=v_account AND {LIVE}
            ORDER BY b.browser_id=p_browser DESC, b.created_at DESC, b.browser_id
            OFFSET 10)
        RETURNING 1)
    INSERT INTO execbound.user_security_events(account_id,kind,occurred_at)
        SELECT v_account,'trusted_browser_removed',p_now FROM removed;
    RETURN v_expires;
END $$
"""

USE = f"""
CREATE FUNCTION execbound.trusted_browser_use(p_tenant uuid, p_session uuid, p_browser uuid,
    p_hash text, p_token_hash text, p_csrf_hash text, p_now timestamptz)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    t uuid := nullif(current_setting('execbound.tenant_id',true),'')::uuid;
    s execbound.human_sessions; v_account uuid; u execbound.user_accounts;
    f execbound.user_factors; b execbound.trusted_browsers;
BEGIN
{SESSION}
    IF p_token_hash IS NULL OR p_token_hash !~ '^[0-9a-f]{{64}}$' OR p_csrf_hash IS NULL
        OR p_csrf_hash !~ '^[0-9a-f]{{64}}$' THEN RAISE EXCEPTION 'INVALID_SESSION'; END IF;
    IF f.enabled_at IS NULL THEN RETURN false; END IF;
    IF EXISTS(SELECT 1 FROM execbound.account_security_policy p WHERE p.tenant_id=t
        AND NOT p.allow_trusted_browsers) THEN RETURN false; END IF;
    -- A session that already holds a verification of the current factor keeps it.
    IF EXISTS(SELECT 1 FROM execbound.session_assurance a WHERE a.tenant_id=t
        AND a.session_id=p_session AND a.version=f.version) THEN RETURN false; END IF;
    SELECT * INTO b FROM execbound.trusted_browsers
        WHERE account_id=v_account AND browser_id=p_browser FOR UPDATE;
    -- A plain comparison is enough: both sides are SHA-256 digests, and the caller controls only
    -- the preimage, so how long a comparison takes says nothing about the stored digest.
    IF b.browser_id IS NULL OR p_hash IS NULL OR b.token_hash<>p_hash
        OR NOT coalesce({LIVE}, false) THEN RETURN false; END IF;
    -- The trust's own verification time, never now: the step-up still reads its age.
    INSERT INTO execbound.session_assurance(tenant_id,session_id,version,verified_at,method)
        VALUES(t,p_session,f.version,b.verified_at,'trusted')
        ON CONFLICT(tenant_id,session_id) DO UPDATE SET version=excluded.version,
            verified_at=excluded.verified_at,method=excluded.method;
    UPDATE execbound.trusted_browsers SET last_used_at=p_now
        WHERE account_id=v_account AND browser_id=p_browser;
    -- The session is rotated with the assurance, as `rotate_session` does after a code: the
    -- token issued before the factor was satisfied no longer loads.
    UPDATE execbound.human_sessions SET token_hash=p_token_hash,csrf_hash=p_csrf_hash
        WHERE tenant_id=t AND session_id=p_session;
    RETURN true;
END $$
"""

# The account and factor rows the live predicate reads, for the account in context.
ACCOUNT_ROWS = """
    IF p_account IS NULL OR p_account IS DISTINCT FROM
        nullif(current_setting('execbound.account_id',true),'')::uuid
        THEN RAISE EXCEPTION 'INVALID_ACCOUNT'; END IF;
    SELECT * INTO u FROM execbound.user_accounts WHERE account_id=p_account;
    SELECT * INTO f FROM execbound.user_factors WHERE account_id=p_account;
"""

REMOVE = f"""
CREATE FUNCTION execbound.trusted_browser_remove(p_account uuid, p_browser uuid,
    p_now timestamptz)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    u execbound.user_accounts; f execbound.user_factors; n integer;
BEGIN
{ACCOUNT_ROWS}
    WITH removed AS (
        UPDATE execbound.trusted_browsers b SET revoked_at=p_now
        WHERE b.account_id=p_account AND b.browser_id=p_browser AND {LIVE}
        RETURNING 1)
    INSERT INTO execbound.user_security_events(account_id,kind,occurred_at)
        SELECT p_account,'trusted_browser_removed',p_now FROM removed;
    GET DIAGNOSTICS n = ROW_COUNT;
    RETURN n>0;
END $$
"""

REMOVE_ALL = f"""
CREATE FUNCTION execbound.trusted_browser_remove_all(p_account uuid, p_now timestamptz)
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    u execbound.user_accounts; f execbound.user_factors; n integer;
BEGIN
{ACCOUNT_ROWS}
    WITH removed AS (
        UPDATE execbound.trusted_browsers b SET revoked_at=p_now
        WHERE b.account_id=p_account AND {LIVE}
        RETURNING 1)
    INSERT INTO execbound.user_security_events(account_id,kind,occurred_at)
        SELECT p_account,'trusted_browser_removed',p_now FROM removed;
    GET DIAGNOSTICS n = ROW_COUNT;
    RETURN n;
END $$
"""

POLICY = """
CREATE FUNCTION execbound.trusted_browser_policy(p_tenant uuid, p_principal uuid,
    p_allow boolean, p_now timestamptz)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    t uuid := nullif(current_setting('execbound.tenant_id',true),'')::uuid;
BEGIN
    IF t IS NULL OR p_tenant IS DISTINCT FROM t THEN RAISE EXCEPTION 'INVALID_TENANT'; END IF;
    -- A workspace administrator: an active principal whose effective kind is ADMIN, and not
    -- one narrowed to their spaces (`0074_workspace_settings_admin`'s words), since the switch
    -- is the whole workspace's.
    IF p_principal IS NULL OR p_allow IS NULL OR NOT EXISTS(
            SELECT 1 FROM execbound.principals p WHERE p.tenant_id=t
            AND p.principal_id=p_principal AND p.active
            AND execbound.access_effective_kind(p_principal)='ADMIN')
        OR (NOT execbound.access_has_permission(p_principal,'access.manage',NULL,false)
            AND EXISTS(SELECT 1 FROM execbound.space_members m
                WHERE m.tenant_id=t AND m.principal_id=p_principal))
        THEN RAISE EXCEPTION 'INVALID_IDENTITY'; END IF;
    INSERT INTO execbound.account_security_policy(tenant_id,requirement,changed_at,changed_by,
        allow_trusted_browsers) VALUES(t,'optional',p_now,p_principal,p_allow)
        ON CONFLICT(tenant_id) DO UPDATE SET
            allow_trusted_browsers=excluded.allow_trusted_browsers,
            changed_at=excluded.changed_at,changed_by=excluded.changed_by;
END $$
"""

# "Sign out other devices" from a session with no account sign-in (a setup credential's, or
# one issued before account sign-in) whose membership links an account: the account path's
# `account_session_revoke` moves the account's version, which ends every trust, and this does
# the same for that session. The account's version moves, the acting session is brought to the
# new version so it alone stays, and every account sign-in of the account ends, since none of
# them is this session. It answers false, changing nothing, when no account is linked.
SIGN_OUT_OTHERS = """
CREATE FUNCTION execbound.account_sign_out_others(p_tenant uuid, p_session uuid,
    p_now timestamptz)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    t uuid := nullif(current_setting('execbound.tenant_id',true),'')::uuid;
    s execbound.human_sessions; v_account uuid; u execbound.user_accounts;
BEGIN
    IF t IS NULL OR p_tenant IS DISTINCT FROM t THEN RAISE EXCEPTION 'INVALID_TENANT'; END IF;
    IF p_now IS NULL THEN RAISE EXCEPTION 'INVALID_SESSION'; END IF;
    SELECT * INTO s FROM execbound.human_sessions WHERE tenant_id=t AND session_id=p_session;
    IF s.session_id IS NULL OR s.account_id IS NOT NULL OR s.revoked_at IS NOT NULL
        OR p_now<s.created_at OR p_now>=s.expires_at OR NOT EXISTS(
          SELECT 1 FROM execbound.credentials c JOIN execbound.principals p
              USING(tenant_id,principal_id)
          WHERE c.tenant_id=t AND c.credential_id=s.credential_id AND p.active
            AND c.revoked_at IS NULL AND c.expires_at>p_now AND p.kind=s.kind
        ) THEN RAISE EXCEPTION 'INVALID_SESSION'; END IF;
    SELECT m.account_id INTO v_account FROM execbound.workspace_memberships m
        WHERE m.tenant_id=t AND m.principal_id=s.principal_id AND m.active
        AND m.version=s.membership_version;
    IF v_account IS NULL THEN RETURN false; END IF;
    PERFORM set_config('execbound.account_id',v_account::text,true);
    SELECT * INTO u FROM execbound.user_accounts WHERE account_id=v_account FOR UPDATE;
    IF u.account_id IS NULL OR NOT u.active OR s.account_version IS DISTINCT FROM u.version
        THEN RAISE EXCEPTION 'INVALID_SESSION'; END IF;
    UPDATE execbound.user_accounts SET version=version+1 WHERE account_id=v_account;
    UPDATE execbound.human_sessions SET account_version=u.version+1
        WHERE tenant_id=t AND session_id=p_session;
    UPDATE execbound.account_sessions SET revoked_at=p_now
        WHERE account_id=v_account AND revoked_at IS NULL;
    INSERT INTO execbound.user_security_events(account_id,kind,occurred_at)
        VALUES(v_account,'other_devices_signed_out',p_now);
    RETURN true;
END $$
"""

DEFINERS = (
    (
        ADD,
        "trusted_browser_add(uuid,uuid,uuid,text,text,text,timestamptz,timestamptz)",
    ),
    (USE, "trusted_browser_use(uuid,uuid,uuid,text,text,text,timestamptz)"),
    (REMOVE, "trusted_browser_remove(uuid,uuid,timestamptz)"),
    (REMOVE_ALL, "trusted_browser_remove_all(uuid,timestamptz)"),
    (POLICY, "trusted_browser_policy(uuid,uuid,boolean,timestamptz)"),
    (SIGN_OUT_OTHERS, "account_sign_out_others(uuid,uuid,timestamptz)"),
)

# Method `trusted` is never a fresh verification. The `fresh` read of both security-change
# functions, as `0067_step_up_window` left it, and the carry read of `account_switch`, as
# `0089_assurance_carry` wrote it.
FRESH = (
    "AND a.verified_at<=p_now AND a.verified_at>p_now-interval '30 minutes');",
    "AND a.verified_at<=p_now AND a.verified_at>p_now-interval '30 minutes'\n"
    "        AND a.method<>'trusted');",
)
CARRY = (
    "          AND sa.verified_at>p_now-interval '30 minutes';",
    "          AND sa.verified_at>p_now-interval '30 minutes'\n"
    "          -- A trusted sign-in is never carried: the destination may forbid trust (0101).\n"
    "          AND sa.method<>'trusted';",
)
PATCHES = (
    ("account_security_change", FRESH),
    ("user_security_change", FRESH),
    ("account_switch", CARRY),
)


def _replace(function: str, before: str, after: str) -> None:
    conn = op.get_bind()
    definition = conn.execute(
        text(
            "SELECT pg_get_functiondef(p.oid) FROM pg_proc p "
            "JOIN pg_namespace n ON n.oid = p.pronamespace "
            "WHERE n.nspname = 'execbound' AND p.proname = :name"
        ),
        {"name": function},
    ).scalar_one()
    # A definition that no longer carries the fragment exactly once was changed by something
    # this migration does not know, and is refused rather than guessed at.
    if definition.count(before) != 1:
        raise RuntimeError(f"{function} no longer has the fragment {revision} patches")
    # Straight to the driver, every percent sign doubled: psycopg reads `%` as a placeholder.
    conn.exec_driver_sql(definition.replace(before, after).replace("%", "%%"))


def _role_exists(role: str) -> bool:
    return bool(
        op.get_bind()
        .execute(text("SELECT 1 FROM pg_roles WHERE rolname = :role"), {"role": role})
        .scalar()
    )


def _method_check(methods: str) -> None:
    op.execute(
        "ALTER TABLE execbound.session_assurance "
        "DROP CONSTRAINT session_assurance_method_check, "
        f"ADD CONSTRAINT session_assurance_method_check CHECK(method IN ({methods}))"
    )


def upgrade() -> None:
    roles = [role for role in SUPABASE_ROLES if _role_exists(role)]
    op.execute(f"""
        CREATE TABLE execbound.trusted_browsers(
            account_id uuid NOT NULL REFERENCES execbound.user_accounts,
            browser_id uuid NOT NULL,
            token_hash text NOT NULL CHECK(token_hash ~ '^[0-9a-f]{{64}}$'),
            account_version bigint NOT NULL CHECK(account_version>0),
            factor_version integer NOT NULL,
            verified_at timestamptz NOT NULL,
            method text NOT NULL CHECK(method IN ({METHODS})),
            label text CHECK(label IS NULL OR length(label) BETWEEN 1 AND 64),
            created_at timestamptz NOT NULL,
            expires_at timestamptz NOT NULL,
            last_used_at timestamptz,
            revoked_at timestamptz,
            PRIMARY KEY(account_id,browser_id),
            CHECK(verified_at<=created_at AND expires_at>created_at
                AND expires_at<=created_at+interval '30 days'),
            CHECK(last_used_at IS NULL OR last_used_at>=created_at),
            CHECK(revoked_at IS NULL OR revoked_at>=created_at)
        )
    """)
    op.execute("ALTER TABLE execbound.trusted_browsers ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE execbound.trusted_browsers FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY account_isolation ON execbound.trusted_browsers "
        f"USING(account_id={ACCOUNT}) WITH CHECK(account_id={ACCOUNT})"
    )
    op.execute("REVOKE ALL ON execbound.trusted_browsers FROM PUBLIC,execbound_app")
    for role in roles:
        op.execute(f"REVOKE ALL ON execbound.trusted_browsers FROM {role}")
    op.execute("GRANT SELECT ON execbound.trusted_browsers TO execbound_app")
    _method_check(METHODS + ",'trusted'")
    op.execute(
        "ALTER TABLE execbound.account_security_policy "
        "ADD COLUMN allow_trusted_browsers boolean NOT NULL DEFAULT true"
    )
    for body, signature in DEFINERS:
        op.execute(body)
        op.execute(f"REVOKE ALL ON FUNCTION execbound.{signature} FROM PUBLIC")
        for role in roles:
            op.execute(f"REVOKE ALL ON FUNCTION execbound.{signature} FROM {role}")
        op.execute(f"GRANT EXECUTE ON FUNCTION execbound.{signature} TO execbound_app")
    for function, (before, after) in PATCHES:
        _replace(function, before, after)


def downgrade() -> None:
    for function, (before, after) in reversed(PATCHES):
        _replace(function, after, before)
    for _, signature in reversed(DEFINERS):
        op.execute(f"DROP FUNCTION execbound.{signature}")
    # A session signed in through trust owes its factor again before the old check returns.
    op.execute("ALTER TABLE execbound.session_assurance NO FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security = off")
    op.execute("DELETE FROM execbound.session_assurance WHERE method='trusted'")
    op.execute("RESET row_security")
    op.execute("ALTER TABLE execbound.session_assurance FORCE ROW LEVEL SECURITY")
    _method_check(METHODS)
    op.execute("ALTER TABLE execbound.account_security_policy DROP COLUMN allow_trusted_browsers")
    op.execute("DROP TABLE execbound.trusted_browsers")
