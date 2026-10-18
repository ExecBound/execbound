# SPDX-License-Identifier: AGPL-3.0-only
"""A provider's verified address completes the same Community signup request (#504).

Design: `docs/superpowers/specs/2026-10-02-provider-signup-design.md`, "Storage and the
boundary" and "The callback" step 4. `signup_requests` gains two columns, `completion_provider`
and `completion_subject`, both null or both set, holding a live provider completion on the
link's own token columns: `verify_token_hash`, `verify_expires_at`, `verify_failures` and
`verify_generation` are the completion's too, so attaching one replaces whichever proof -- a
link or an earlier provider attempt -- was live, exactly as a resend replaces an unopened link.

`signup_provider_attach` is `admit`'s advisory count and `signup_verify_queue`'s QUEUED-to-
VERIFYING transition, reached from a provider's own callback instead of a mailed link, minting
no message; it also supersedes a verification email still `PENDING`, the way
`workspace_invitation_accept` (0059) supersedes an invitation's own message.
`community_provision_provider` creates the account with no password and its `user_identities`
binding, then hands the workspace entirely to `community_provision`'s own signed-in branch, so
the two signup paths cannot drift apart. A completion is spent only through that hand-off:
`community_provision` itself now refuses a request holding one, so the same live token can
never also complete the password or signed-in branch directly, and `signup_verify_check`
answers NULL for it, so `/signup/verify` never renders a password form for a provider token.

A message already `IN_FLIGHT` when attach runs is left alone (attach's own comment below), and
if its own send later suffers a transient fault and comes back `PENDING`, the worker's retry
mints a fresh digest through `signup_verify_rekey` -- which must never spend the completion
attach just proved live. `signup_verify_rekey` now refuses with `INVALID_STATE` while a
completion is live (`completion_subject IS NOT NULL AND verify_expires_at > p_now`), which
`_send`/`_settle` already treat as terminal, failing that one attempt rather than wiping the
completion; an expired completion is nulled and the rekey proceeds, exactly as it always has
for a lapsed link. `signup_verify_queue`'s own `VERIFYING` (resend) branch, reached only from
an explicit resend and never from the worker's own retry, still ends a live completion
outright, its token included: the person asked for a new link, so whatever the provider's
own completion was proving no longer applies, and the request waits with no digest and no
expiry, as a just-queued link does, until the send mints one.

Five existing functions -- `community_provision`, `signup_verify_check`, `signup_verify_rekey`,
`signup_mark` and `signup_verify_queue` -- are patched in seven fragments total, as
`0066_max_agents` and `0067_step_up_window` patch theirs: the live definition is read, each
fragment must occur in it exactly once, and `CREATE OR REPLACE` keeps the owner, `SECURITY
DEFINER` and the grants.

Both new functions belong only to the hosted plugin, following `0065_dormant_grants`'s and
`0063_personal_access_tokens`'s revoke convention: owner grant only, nothing for PUBLIC or the
runtime role. `execbound hosted-upgrade` is what grants them, through `hosted/grants.py`'s
`CLAIMS`.
"""

from alembic import op
from sqlalchemy import text

revision = "0069_provider_signup"
down_revision = "0068_security_signals"
branch_labels = None
depends_on = None

SIGNATURES = (
    "signup_provider_attach(uuid, text, text, text, boolean, integer, timestamptz)",
    "community_provision_provider(uuid, text, uuid, uuid, uuid, text, text, integer, timestamptz)",
)

ATTACH = r"""
CREATE FUNCTION execbound.signup_provider_attach(
    p_request uuid, p_provider text, p_subject text, p_token_hash text, p_admit boolean,
    p_capacity integer, p_now timestamptz)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_request execbound.signup_requests%ROWTYPE;
    v_occupied integer;
BEGIN
    IF v_tenant IS NULL OR p_request IS NULL OR p_token_hash IS NULL
       OR p_token_hash !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'INVALID_DIGEST';
    END IF;
    IF p_now IS NULL OR abs(extract(epoch FROM (p_now - now()))) > 300 THEN
        RAISE EXCEPTION 'INVALID_CLOCK';
    END IF;
    IF p_provider IS NULL OR p_provider NOT IN ('google', 'github')
       OR p_subject IS NULL OR length(p_subject) NOT BETWEEN 1 AND 255 THEN
        RAISE EXCEPTION 'INVALID_SUBJECT';
    END IF;
    IF p_admit IS NULL OR p_capacity IS NULL OR p_capacity < 1 THEN
        RAISE EXCEPTION 'INVALID_REQUEST';
    END IF;
    SELECT * INTO v_request FROM execbound.signup_requests r
     WHERE r.tenant_id = v_tenant AND r.request_id = p_request FOR UPDATE;
    IF NOT FOUND OR v_request.email IS NULL THEN
        RAISE EXCEPTION 'INVALID_REQUEST';
    END IF;
    IF v_request.state = 'QUEUED' AND p_admit THEN
        -- The same advisory count `signups._occupied` takes: a workspace made, plus a link
        -- still live. A full house waitlists the request exactly as an admitted email does,
        -- and queues no message of its own; the caller's own waitlist insert is what notes it.
        SELECT count(*) INTO v_occupied FROM execbound.signup_requests r
         WHERE r.tenant_id = v_tenant
           AND (r.state = 'PROVISIONED'
                OR (r.state = 'VERIFYING'
                    AND (r.verify_expires_at IS NULL OR r.verify_expires_at > p_now)));
        IF v_occupied >= p_capacity THEN
            RETURN 'FULL';
        END IF;
        UPDATE execbound.signup_requests
           SET state = 'VERIFYING', verifying_at = p_now, verify_sends = 0
         WHERE tenant_id = v_tenant AND request_id = p_request;
    ELSIF v_request.state <> 'VERIFYING' THEN
        -- Admission without `p_admit`, or any other state (`INVITED`, `CLAIMED`, `EXPIRED`,
        -- `REFUSED`, `PROVISIONED`): nothing changes, and the caller reads its own state back
        -- rather than this function waitlisting or attaching on its behalf.
        RETURN v_request.state;
    END IF;
    -- A newer proof replaces an older one either way: this ends an emailed link exactly as a
    -- resend does, on the link's own token columns, which `signup_verify_check` still reads.
    UPDATE execbound.signup_requests
       SET verify_generation = verify_generation + 1, verify_token_hash = p_token_hash,
           verify_expires_at = p_now + interval '30 minutes', verify_failures = 0,
           completion_provider = p_provider, completion_subject = p_subject
     WHERE tenant_id = v_tenant AND request_id = p_request;
    -- The provider just proved the address, so a verification email still waiting to go out
    -- would only confuse its reader; superseded exactly as `workspace_invitation_accept`
    -- (0059) supersedes a `PENDING` invitation message of its own. One already `IN_FLIGHT` is
    -- left alone: the attempt already under way is not recalled.
    UPDATE execbound.signup_messages
       SET state = 'FAILED', last_error = 'ATTACHED'
     WHERE tenant_id = v_tenant AND request_id = p_request
       AND message_class = 'verification' AND state = 'PENDING';
    RETURN 'VERIFYING';
END $$
"""

PROVISION_PROVIDER = r"""
CREATE FUNCTION execbound.community_provision_provider(
    p_request uuid, p_token_hash text, p_tenant uuid, p_principal uuid, p_account uuid,
    p_name text, p_slug text, p_capacity integer, p_now timestamptz)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_operator uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_request execbound.signup_requests%ROWTYPE;
    v_provider text;
    v_made jsonb;
BEGIN
    IF v_operator IS NULL OR p_request IS NULL OR p_tenant IS NULL OR p_principal IS NULL
       OR p_account IS NULL OR p_token_hash IS NULL OR p_token_hash !~ '^[0-9a-f]{64}$'
       OR p_capacity IS NULL OR p_capacity < 1 THEN
        RAISE EXCEPTION 'INVALID_REQUEST';
    END IF;
    IF p_now IS NULL OR abs(extract(epoch FROM (p_now - now()))) > 300 THEN
        RAISE EXCEPTION 'INVALID_CLOCK';
    END IF;
    IF p_name IS NULL OR p_name <> btrim(p_name) OR length(p_name) NOT BETWEEN 1 AND 120 THEN
        RAISE EXCEPTION 'INVALID_NAME';
    END IF;
    IF p_slug IS NULL OR p_slug !~ '^[a-z0-9]+(-[a-z0-9]+)*$'
       OR length(p_slug) NOT BETWEEN 3 AND 63 THEN
        RAISE EXCEPTION 'INVALID_SLUG';
    END IF;

    -- 1. The request, under the same failure-count and expiry rules `community_provision`'s
    --    own steps 1 and 2 apply. The caller holds the operator tenant's fence, which
    --    serializes this against every other submission, admission and completion.
    SELECT * INTO v_request FROM execbound.signup_requests r
     WHERE r.tenant_id = v_operator AND r.request_id = p_request FOR UPDATE;
    IF NOT FOUND OR v_request.email IS NULL OR v_request.verify_token_hash IS NULL
       OR v_request.verify_failures >= 5 THEN
        RETURN NULL;
    END IF;
    IF v_request.verify_token_hash <> p_token_hash THEN
        UPDATE execbound.signup_requests SET verify_failures = verify_failures + 1
         WHERE tenant_id = v_operator AND request_id = p_request;
        RETURN NULL;
    END IF;
    IF v_request.state = 'PROVISIONED' THEN
        RETURN jsonb_build_object('outcome', 'ALREADY',
                                  'tenant_id', v_request.provisioned_tenant_id);
    END IF;
    IF v_request.state <> 'VERIFYING' OR v_request.verify_expires_at <= p_now THEN
        RAISE EXCEPTION 'INVALID_TOKEN';
    END IF;
    IF v_request.completion_subject IS NULL THEN
        -- The live token is a link's own, not a provider's: that proof completes through
        -- `community_provision` directly, never here.
        RAISE EXCEPTION 'INVALID_TOKEN';
    END IF;
    v_provider := v_request.completion_provider;

    -- 2. Capacity, retaken authoritatively before anything is created. The operator fence
    --    held since step 1 is what makes this agree with `community_provision`'s own recheck
    --    in step 5: nothing else can move the PROVISIONED count while this transaction holds
    --    the fence, so the two counts can never disagree.
    IF (SELECT count(*) FROM execbound.signup_requests r
         WHERE r.tenant_id = v_operator AND r.state = 'PROVISIONED') >= p_capacity THEN
        UPDATE execbound.signup_requests
           SET state = 'QUEUED', verify_token_hash = NULL, verify_expires_at = NULL,
               completion_provider = NULL, completion_subject = NULL
         WHERE tenant_id = v_operator AND request_id = p_request;
        INSERT INTO execbound.signup_messages
            (tenant_id, message_id, request_id, message_class, created_at, next_attempt_at)
        VALUES (v_operator, gen_random_uuid(), p_request, 'waitlist', p_now, p_now)
        ON CONFLICT (tenant_id, request_id, message_class) DO NOTHING;
        RETURN jsonb_build_object('outcome', 'CAPACITY');
    END IF;

    -- 3. The account and its binding, locked before any tenant row is written, exactly as
    --    `community_provision`'s own password branch locks its account. The marker is what
    --    the `sign_in_email` policies read, so both lookups below see every tenant under
    --    forced row level security, copied byte for byte from that branch.
    PERFORM set_config('execbound.sign_in_email', v_request.email, true);
    IF EXISTS (SELECT 1 FROM execbound.user_accounts WHERE email = v_request.email)
       OR EXISTS (SELECT 1 FROM execbound.principals p
                   WHERE p.email = v_request.email AND p.active
                     AND p.kind IN ('ADMIN', 'HUMAN_APPROVER')) THEN
        RAISE EXCEPTION 'ACCOUNT_EXISTS';
    END IF;
    PERFORM set_config('execbound.sign_in_email', '', true);
    -- The one marker `user_security_change`'s `link_finish` branch relies on: it is set once,
    -- to the account a session names, before that branch's own insert into `user_identities`.
    -- Set here to the account this function is creating, it is what lets both the insert
    -- below and the one that follows it pass `user_accounts` and `user_identities`'s
    -- `account_isolation` policy under forced row level security. Removing this line breaks
    -- every owner's run already, bypassing or not: `community_provision`'s own branch
    -- selection, two steps below, reads this same setting to choose its signed-in branch over
    -- its password one, so a missing marker answers `INVALID_REQUEST` everywhere, not just on
    -- a hosted database. What only an owner that does not bypass -- a hosted database, or this
    -- suite's own non-bypassing `stack` fixture (`tests/hosted/test_signup_without_bypass.py`)
    -- -- actually proves is that the inserts' own `account_isolation` policy is satisfied: that
    -- this line's value is the right one, not merely present.
    PERFORM set_config('execbound.account_id', p_account::text, true);
    BEGIN
        INSERT INTO execbound.user_accounts(account_id, email, email_verified_at)
        VALUES (p_account, v_request.email, p_now);
    EXCEPTION WHEN unique_violation THEN
        RAISE EXCEPTION 'ACCOUNT_EXISTS';
    END;
    BEGIN
        INSERT INTO execbound.user_identities(account_id, provider, subject, email,
            display_name, created_at)
        VALUES (p_account, v_provider, v_request.completion_subject, v_request.email,
            NULL, p_now);
    EXCEPTION WHEN unique_violation THEN
        -- Another account bound this subject in the meantime; the primary key refuses it.
        RAISE EXCEPTION 'ACCOUNT_EXISTS';
    END;

    -- 4. The completion is spent the moment it hands off: cleared here, before
    --    `community_provision` ever re-reads this row, because that function now refuses any
    --    request still holding one (its own patch below). Nulling it here rather than
    --    leaving it to a branch inside `community_provision` is what makes that refusal
    --    reachable at all -- a call that found its own completion live would refuse itself.
    UPDATE execbound.signup_requests
       SET completion_provider = NULL, completion_subject = NULL
     WHERE tenant_id = v_operator AND request_id = p_request;

    -- 5. The workspace: `community_provision`'s own signed-in branch, so the two signup
    --    paths cannot drift apart. `execbound.account_id` already names the account just
    --    created above, so that call reaches the signed-in branch rather than the password
    --    one.
    PERFORM set_config('execbound.tenant_id', v_operator::text, true);
    v_made := execbound.community_provision(p_request, p_token_hash, p_tenant, p_principal,
                                             NULL, p_name, p_slug, NULL, p_capacity, p_now);
    IF v_made IS NULL OR v_made ->> 'outcome' IS DISTINCT FROM 'PROVISIONED' THEN
        RAISE EXCEPTION 'INVALID_STATE';
    END IF;

    -- 6. A legacy holder who became active while this ran is the same refusal the password
    --    branch gives after its own principal write (community_provision's own step 3); the
    --    signed-in branch that step 5 just took skips it, because community_provision never
    --    expects a brand new account to arrive on that branch. `p_tenant` is excluded not
    --    because its new ADMIN is guaranteed to carry the address -- community_provision's own
    --    principal email UPDATE can itself lose a unique violation and leave it NULL -- but
    --    because this recheck is only ever about a legacy holder somewhere else.
    PERFORM set_config('execbound.sign_in_email', v_request.email, true);
    IF EXISTS (SELECT 1 FROM execbound.principals p
                WHERE p.email = v_request.email AND p.active
                  AND p.kind IN ('ADMIN', 'HUMAN_APPROVER') AND p.tenant_id <> p_tenant) THEN
        RAISE EXCEPTION 'ACCOUNT_EXISTS';
    END IF;
    PERFORM set_config('execbound.sign_in_email', '', true);

    RETURN v_made || jsonb_build_object('provider', v_provider);
END $$
"""

# Each (function, old fragment, new fragment), applied in order on upgrade and undone in
# reverse on downgrade, following `0066_max_agents`'s and `0067_step_up_window`'s technique:
# migrations never import each other, so `_replace` below is `0066`'s own, copied.
PATCHES = (
    # The boundary between the two proofs: a request holding a live provider completion can
    # complete only through `community_provision_provider`'s hand-off, which clears the
    # completion before ever making this call. A direct call -- the password branch or the
    # signed-in branch, from the emailed link's own page -- is refused before either branch is
    # chosen, so a provider's token can never also create a password account with no binding.
    # Once this holds, nothing can reach `community_provision`'s own CAPACITY or PROVISIONED
    # branches with a completion still set, so neither needs its own nulling patch any more.
    (
        "community_provision",
        "    IF v_request.state <> 'VERIFYING' OR v_request.verify_expires_at <= p_now THEN\n"
        "        RAISE EXCEPTION 'INVALID_TOKEN';\n"
        "    END IF;",
        "    IF v_request.state <> 'VERIFYING' OR v_request.verify_expires_at <= p_now THEN\n"
        "        RAISE EXCEPTION 'INVALID_TOKEN';\n"
        "    END IF;\n"
        "    IF v_request.completion_subject IS NOT NULL THEN\n"
        "        RAISE EXCEPTION 'INVALID_TOKEN';\n"
        "    END IF;",
    ),
    # The signup page never shows a password form for a token only a provider can spend: the
    # digest can still match, but a live completion means the one place that may answer it is
    # `community_provision_provider`, not the emailed link's own check.
    (
        "signup_verify_check",
        "    IF v_request.verify_token_hash <> p_token_hash THEN\n"
        "        UPDATE execbound.signup_requests SET verify_failures = verify_failures + 1\n"
        "         WHERE tenant_id = v_tenant AND request_id = p_request;\n"
        "        RETURN NULL;\n"
        "    END IF;\n"
        "    RETURN jsonb_build_object(",
        "    IF v_request.verify_token_hash <> p_token_hash THEN\n"
        "        UPDATE execbound.signup_requests SET verify_failures = verify_failures + 1\n"
        "         WHERE tenant_id = v_tenant AND request_id = p_request;\n"
        "        RETURN NULL;\n"
        "    END IF;\n"
        "    IF v_request.completion_subject IS NOT NULL THEN\n"
        "        RETURN NULL;\n"
        "    END IF;\n"
        "    RETURN jsonb_build_object(",
    ),
    # An explicit resend -- the person asking outright for a new link -- ends a live provider
    # completion exactly as attach ends an older link: never reached by the worker's own
    # retry (that path is `signup_verify_rekey`'s alone, patched below), only by a fresh call
    # here, so this is always the person asking for a different proof than the one they have.
    # The provider's token goes with it: left on the link's own columns once the completion
    # is cleared, it would read as a link's until the send rekeyed the request, answering
    # `signup_verify_check` and completing `community_provision`'s password branch. The
    # request is left as a just-queued link leaves it, with no digest and no expiry. A link's
    # own token is untouched, as a resend always left it: it stays good until the new one is
    # minted. Every expression reads the row as it was, so the cases see the old subject.
    (
        "signup_verify_queue",
        "SET verify_sends = verify_sends + 1",
        "SET verify_sends = verify_sends + 1,\n"
        "               verify_token_hash = CASE WHEN completion_subject IS NULL\n"
        "                                        THEN verify_token_hash END,\n"
        "               verify_expires_at = CASE WHEN completion_subject IS NULL\n"
        "                                        THEN verify_expires_at END,\n"
        "               completion_provider = NULL, completion_subject = NULL",
    ),
    # A newer link replaces a provider completion's columns as a provider attach replaces an
    # older link's. The second `signup_verify_rekey` fragment below lets the rekey run only
    # when no completion is held or the one held has expired, so what this clears in practice
    # is an expired completion, nulled as a lapsed link's digest is overwritten.
    (
        "signup_verify_rekey",
        "SET verify_generation = verify_generation + 1, verify_token_hash = p_token_hash,\n"
        "           verify_expires_at = p_now + interval '30 minutes', verify_failures = 0",
        "SET verify_generation = verify_generation + 1, verify_token_hash = p_token_hash,\n"
        "           verify_expires_at = p_now + interval '30 minutes', verify_failures = 0,\n"
        "           completion_provider = NULL, completion_subject = NULL",
    ),
    # Unlike an explicit resend, the worker's own retry after a transient send fault must
    # never reach that same clearing: a message already `IN_FLIGHT` when attach ran was left
    # alone, so a completion still live here is the one attach proved, not a stale one a link
    # ever held. Refused with `INVALID_STATE`, which `_send`/`_settle` already treat as
    # terminal (I1, `tests/hosted/test_community_signup.py`'s `test_vs6b`), rather than spent;
    # a completion that has already expired is no different from a lapsed link, so it is
    # nulled and the rekey proceeds exactly as it always has.
    (
        "signup_verify_rekey",
        "WHERE tenant_id = v_tenant AND request_id = p_request AND state = 'VERIFYING'\n"
        "       AND email IS NOT NULL",
        "WHERE tenant_id = v_tenant AND request_id = p_request AND state = 'VERIFYING'\n"
        "       AND email IS NOT NULL\n"
        "       AND (completion_subject IS NULL OR verify_expires_at <= p_now)",
    ),
    # `signup_mark`'s purge pass: a completion nobody used is held no longer than the address
    # it came with.
    (
        "signup_mark",
        "UPDATE execbound.signup_requests SET email = NULL, purge_after = NULL\n"
        "         WHERE tenant_id = v_tenant AND email IS NOT NULL",
        "UPDATE execbound.signup_requests\n"
        "           SET email = NULL, purge_after = NULL, completion_provider = NULL,\n"
        "               completion_subject = NULL\n"
        "         WHERE tenant_id = v_tenant AND email IS NOT NULL",
    ),
    # `signup_mark`'s lapse: an unopened link and an unused provider completion both die with
    # the request that was never finished, exactly as `_lapse` ends an unopened link today.
    (
        "signup_mark",
        "verify_token_hash = CASE WHEN p_state = 'EXPIRED' THEN NULL\n"
        "                                    ELSE verify_token_hash END\n"
        "     WHERE tenant_id = v_tenant AND request_id = p_request",
        "verify_token_hash = CASE WHEN p_state = 'EXPIRED' THEN NULL\n"
        "                                    ELSE verify_token_hash END,\n"
        "           completion_provider = CASE WHEN p_state = 'EXPIRED' THEN NULL\n"
        "                                    ELSE completion_provider END,\n"
        "           completion_subject = CASE WHEN p_state = 'EXPIRED' THEN NULL\n"
        "                                    ELSE completion_subject END\n"
        "     WHERE tenant_id = v_tenant AND request_id = p_request",
    ),
)


def _replace(function: str, before: str, after: str, *, reverse: bool = False) -> None:
    # Four of these seven fragments -- `community_provision`'s, `signup_verify_queue`'s and
    # both of `signup_verify_rekey`'s -- keep `before` as a literal prefix of `after`, so a
    # definition that already carries the forward patch still carries the pre-patch fragment
    # too, as a substring of the new one. For those four, the re-application guard below
    # would misfire on every legitimate downgrade if it also ran in reverse, finding the old
    # fragment it is about to restore already sitting inside the definition it just read. The
    # other three fragments happen not to, but `_replace` is the same call for every fragment
    # here, so the guard runs forwards only, for all seven alike.
    if reverse:
        before, after = after, before
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
    # A forward call whose replacement already occurs was already applied by an earlier run of
    # this same migration; applying it again would silently duplicate it rather than replace
    # it once, so it is refused for the same reason a missing `before` is.
    if not reverse and after in definition:
        raise RuntimeError(f"{function} already has the fragment {revision} would reapply")
    # CREATE OR REPLACE keeps the owner, SECURITY DEFINER and the grants. Straight to the
    # driver, every percent sign doubled: psycopg reads `%` as a placeholder, and these
    # declare `%ROWTYPE` variables.
    conn.exec_driver_sql(definition.replace(before, after).replace("%", "%%"))


def role_exists(role: str) -> bool:
    return bool(
        op.get_bind()
        .execute(text("SELECT 1 FROM pg_roles WHERE rolname = :role"), {"role": role})
        .scalar()
    )


def upgrade() -> None:
    op.execute("""
        ALTER TABLE execbound.signup_requests
            ADD COLUMN completion_provider text
                CHECK (completion_provider IN ('google', 'github')),
            ADD COLUMN completion_subject text
                CHECK (length(completion_subject) BETWEEN 1 AND 255),
            ADD CONSTRAINT signup_requests_completion CHECK (
                (completion_provider IS NULL) = (completion_subject IS NULL))
    """)
    for body in (ATTACH, PROVISION_PROVIDER):
        op.execute(body)
    # The revoke convention of `0063_personal_access_tokens` and `0065_dormant_grants`: an
    # object only the hosted plugin uses holds no grant but the owner's from the moment it
    # exists. `REVOKE ALL ... FROM PUBLIC` takes back what `CREATE FUNCTION` grants PUBLIC by
    # default; neither function is ever granted to `execbound_app` or to a Supabase role.
    roles = [role for role in ("anon", "authenticated", "service_role") if role_exists(role)]
    for signature in SIGNATURES:
        op.execute(f"REVOKE ALL ON FUNCTION execbound.{signature} FROM PUBLIC, execbound_app")
        for role in roles:
            op.execute(f"REVOKE ALL ON FUNCTION execbound.{signature} FROM {role}")
    for function, before, after in PATCHES:
        _replace(function, before, after)


def downgrade() -> None:
    # As `0055_community_signup`'s own downgrade refuses to lose a provisioned workspace: a
    # live provider completion is evidence this revision alone holds, on columns the downgrade
    # is about to drop, so it is refused rather than silently discarded. Lifted and restored
    # around the read, exactly as `0055` lifts it, because FORCE ROW LEVEL SECURITY binds the
    # owner too and this check is about every tenant, not the one the connection is fenced to.
    op.execute("ALTER TABLE execbound.signup_requests NO FORCE ROW LEVEL SECURITY")
    populated = bool(
        op.get_bind()
        .execute(
            text(
                "SELECT EXISTS (SELECT 1 FROM execbound.signup_requests "
                "WHERE completion_provider IS NOT NULL)"
            )
        )
        .scalar_one()
    )
    op.execute("ALTER TABLE execbound.signup_requests FORCE ROW LEVEL SECURITY")
    if populated:
        raise RuntimeError(
            "A live provider completion requires a verified full restore; lossy downgrade refused"
        )
    for function, before, after in reversed(PATCHES):
        _replace(function, before, after, reverse=True)
    for signature in SIGNATURES:
        op.execute(f"DROP FUNCTION execbound.{signature}")
    op.execute("""
        ALTER TABLE execbound.signup_requests
            DROP CONSTRAINT signup_requests_completion,
            DROP COLUMN completion_provider,
            DROP COLUMN completion_subject
    """)
