# SPDX-License-Identifier: AGPL-3.0-only
"""The dormant catalog (#496): a plugin's objects hold no runtime grant unless claimed.

Every migration ships in one chain, so the tables and functions only a plugin uses exist on
every install; `check_runtime` requires each to hold exactly what a loaded plugin claims, and
nothing where none does. Real PostgreSQL for everything that reads a grant.
"""

import os
import re
import secrets
from pathlib import Path
from types import MappingProxyType

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text

from execbound.db import (
    DORMANT,
    DORMANT_FUNCTIONS,
    DORMANT_TABLES,
    EMPTY_CLAIMS,
    FUNCTIONS,
    SCHEMA_REVISION,
    TABLES,
    UPDATE_COLUMNS,
    Claims,
    DormantGrantsRefused,
    UnsafeDatabaseRole,
    _runtime_grants,
    _runtime_rows,
    check_dormant,
    check_runtime,
    dormant_grants,
    grant_dormant,
    honour_claims,
)

pytestmark = pytest.mark.integration

# Pinned in full, so a change to the catalog reads as a diff of names.
EXPECTED_TABLES = {
    "community_allocations",
    "product_counts",
    "onboarding_slots",
    "onboarding_invitations",
    "signup_requests",
    "signup_messages",
    "account_preferences",
    # Password reset by email (0085, #678).
    "account_recoveries",
    "account_messages",
    # The advance dormancy warning (0092, #439).
    "dormancy_warnings",
}
EXPECTED_FUNCTIONS = {
    "product_count",
    "onboarding_claim",
    "sandbox_reattest",
    "onboarding_invite",
    "onboarding_invitation_rekey",
    "onboarding_invitation_revoke",
    "sandbox_expire",
    "sandbox_notice",
    "sandbox_fallback",
    "agents_sleep",
    "signup_request",
    "signup_allocate",
    "signup_mark",
    "signup_verify_queue",
    "signup_verify_rekey",
    "signup_verify_check",
    "community_provision",
    # Provider signup (0069, #504): born dormant, unlike the rest of this set, which 0065
    # revoked from grants the runtime already held.
    "signup_provider_attach",
    "community_provision_provider",
    # Password reset by email (0085, #678), born dormant too.
    "account_recovery_request",
    "account_recovery_rekey",
    "account_recovery_check",
    "account_password_recover",
    "account_recovery_lapse",
    # The advance dormancy warning (0092, #439), born dormant too.
    "dormancy_warn",
    "dormancy_warnings_due",
    "dormancy_warnings_sent",
}


def test_dc1_the_catalog_marks_the_dormant_objects_inside_the_core_catalog():
    assert set(DORMANT_TABLES) <= set(TABLES)
    assert set(DORMANT_FUNCTIONS) <= set(FUNCTIONS)
    assert len(set(DORMANT_TABLES)) == len(DORMANT_TABLES) == 10
    names = {name for name, _ in DORMANT_FUNCTIONS}
    assert len(names) == len(DORMANT_FUNCTIONS) == 27
    assert set(DORMANT_TABLES) == EXPECTED_TABLES
    assert names == EXPECTED_FUNCTIONS
    assert DORMANT == EXPECTED_TABLES | EXPECTED_FUNCTIONS
    assert len(DORMANT) == 37
    # Workspace switching (0054), teammate invitations (0059), sample targets (0060),
    # personal access tokens (0063) and the scheduled jobs' directory and scheduler (0064) are
    # core; 0061 patched core functions and 0062 added a core trigger function.
    assert DORMANT.isdisjoint(
        {
            "account_switch",
            "workspace_invitations",
            "workspace_invitation_messages",
            "workspace_invitation_accept",
            "samples_install",
            "samples_remove",
            "number_principal",
            "personal_access_tokens",
            "admin_issue_personal_token",
            "job_tenants",
            "job_tenants_page",
            "scheduler_actor",
            "assistant_turn_retire_due",
        }
    )


def expected(claims: Claims) -> dict[str, frozenset[str]]:
    """What `dormant_grants` reads on a database holding exactly ``claims``."""
    return {name: claims.get(name, frozenset()) for name in DORMANT}


# The revision before `0065_dormant_grants`: the one a release starts from.
BASE = "0064_scheduled_jobs"
NOTHING = expected(EMPTY_CLAIMS)
# What the runtime held on each dormant object before `0065_dormant_grants`, which that
# revision's downgrade restores. A historical snapshot, not a read of the current (growing)
# `DORMANT_FUNCTIONS`: a function born dormant after 0065, provider signup's two among them,
# never held a runtime grant for that revision to take away or give back.
AT_BASE = {
    "community_allocations": frozenset({"SELECT"}),
    "product_counts": frozenset({"SELECT"}),
    "onboarding_slots": frozenset({"SELECT"}),
    "onboarding_invitations": frozenset(
        f"SELECT({column})"
        for column in (
            "tenant_id",
            "invitation_id",
            "note",
            "issued_at",
            "expires_at",
            "redeemed_at",
            "revoked_at",
            "failure_count",
        )
    ),
    "signup_requests": frozenset({"SELECT"}),
    "signup_messages": frozenset(
        {
            "SELECT",
            *(
                f"UPDATE({column})"
                for column in (
                    "state",
                    "attempts",
                    "next_attempt_at",
                    "lease_until",
                    "lease_token",
                    "delivered_at",
                    "last_error",
                )
            ),
        }
    ),
    "account_preferences": frozenset({"SELECT"}),
    **{
        name: frozenset({"EXECUTE"})
        for name in (
            "product_count",
            "onboarding_claim",
            "sandbox_reattest",
            "onboarding_invite",
            "onboarding_invitation_rekey",
            "onboarding_invitation_revoke",
            "sandbox_expire",
            "sandbox_notice",
            "sandbox_fallback",
            "agents_sleep",
            "signup_request",
            "signup_allocate",
            "signup_mark",
            "signup_verify_queue",
            "signup_verify_rekey",
            "signup_verify_check",
            "community_provision",
        )
    },
    # Neither function exists yet at this revision (0069 is what creates them), so
    # `dormant_grants` reads an empty privilege set for each, the same as for any other name
    # in `DORMANT` nothing has granted.
    "signup_provider_attach": frozenset(),
    "community_provision_provider": frozenset(),
    # Password reset by email (#678): created by 0085, so absent here too.
    **{
        name: frozenset()
        for name in (
            "account_recoveries",
            "account_messages",
            "account_recovery_request",
            "account_recovery_rekey",
            "account_recovery_check",
            "account_password_recover",
            "account_recovery_lapse",
        )
    },
    # The advance dormancy warning (#439): created by 0092, so absent here too.
    **{
        name: frozenset()
        for name in (
            "dormancy_warnings",
            "dormancy_warn",
            "dormancy_warnings_due",
            "dormancy_warnings_sent",
        )
    },
}
# `AT_BASE` itself is not a claim `claim_is_valid` accepts once it carries an empty entry: a
# claim of nothing is not a claim of that object at all. This is the part of it worth handing
# to `grant_dormant` as one, for the one test that does.
AT_BASE_CLAIM = MappingProxyType(
    {name: privileges for name, privileges in AT_BASE.items() if privileges}
)
GRANTS = (
    [f"SELECT ON execbound.{table} TO execbound_app" for table in DORMANT_TABLES]
    + [
        f"EXECUTE ON FUNCTION execbound.{name}({arguments}) TO execbound_app"
        for name, arguments in DORMANT_FUNCTIONS
    ]
    # PUBLIC's grants reach the runtime role too.
    + [
        "SELECT ON execbound.onboarding_invitations TO PUBLIC",
        "EXECUTE ON FUNCTION execbound.agents_sleep(timestamp with time zone) TO PUBLIC",
    ]
    # Privileges `check_runtime`'s own table loop never asks about, whole and on one column:
    # only the dormant reading's privilege lists see them. MAINTAIN exists from PostgreSQL 17,
    # which the suite runs on.
    + [
        f"{privilege} ON execbound.product_counts TO execbound_app"
        for privilege in ("TRIGGER", "REFERENCES", "MAINTAIN")
    ]
    + [
        f"{privilege} (note) ON execbound.onboarding_invitations TO execbound_app"
        for privilege in ("INSERT", "REFERENCES")
    ]
)
# `product_count`'s own signature, read from the catalog rather than repeated here.
PRODUCT_COUNT = "execbound.product_count({})".format(dict(DORMANT_FUNCTIONS)["product_count"])
# A claim of one table, whole and on one column, and one function.
CLAIM = MappingProxyType(
    {
        "signup_messages": frozenset({"SELECT", "UPDATE(state)"}),
        "product_count": frozenset({"EXECUTE"}),
    }
)


def alembic_config() -> Config:
    config = Config("alembic.ini")
    config.attributes["database_url"] = os.environ["TEST_MIGRATION_DATABASE_URL"]
    return config


def revision_of(engine) -> str:
    with engine.connect() as conn:
        return conn.execute(text("SELECT version_num FROM execbound.alembic_version")).scalar_one()


def empty_schema(engine) -> None:
    """Every product table emptied, so a downgrade's own refusals see no retained row.

    Only the tables the database's revision holds: a migration test that ends below the head
    empties the schema there before it upgrades, and a later revision's tables do not exist yet.
    """
    with engine.begin() as conn:
        present = set(
            conn.execute(
                text("SELECT tablename FROM pg_tables WHERE schemaname = 'execbound'")
            ).scalars()
        )
        conn.execute(
            text(
                "TRUNCATE "
                + ", ".join(f"execbound.{table}" for table in TABLES if table in present)
            )
        )


def public_executes(conn) -> set[str]:
    return set(
        conn.execute(
            text(
                "SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
                "WHERE n.nspname = 'execbound' AND p.proname = ANY(:names) "
                "AND has_function_privilege('public', p.oid, 'EXECUTE')"
            ),
            {"names": [name for name, _ in DORMANT_FUNCTIONS]},
        ).scalars()
    )


@pytest.fixture
def revoked_afterwards(admin_engine):
    """Every dormant grant taken away after the test, however it ends, so a grant it left
    behind can never be blamed on the next."""
    yield
    with admin_engine.begin() as conn:
        grant_dormant(conn, EMPTY_CLAIMS)


def can_create_roles(engine) -> bool:
    with engine.connect() as conn:
        return conn.execute(
            text("SELECT rolsuper OR rolcreaterole FROM pg_roles WHERE rolname = current_user")
        ).scalar_one()


def test_dc18_the_outbox_columns_are_the_plugins_claim_now():
    assert "signup_messages" not in UPDATE_COLUMNS


def test_dc19_no_core_source_reaches_a_dormant_object():
    """Tests under a plugin's directory run with its grants, so a core path that read a
    dormant object could pass unnoticed there. Every source under `src` outside a plugin
    package (one whose `__init__.py` defines `PLUGIN`) and `execbound/db.py`, the catalog
    itself, is read for a schema-qualified name of one."""
    root = Path(__file__).resolve().parents[1] / "src"
    catalog = root / "execbound" / "db.py"
    plugins = {
        init.parent
        for init in root.rglob("__init__.py")
        if re.search(r"^PLUGIN\s*=", init.read_text(encoding="utf-8"), re.MULTILINE)
    }
    names = re.compile(r"execbound\.(" + "|".join(sorted(DORMANT)) + r")\b")
    found = []
    for path in sorted(root.rglob("*.py")):
        if path == catalog or any(package in path.parents for package in plugins):
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if names.search(line):
                found.append(f"{path.relative_to(root)}:{number}")
    assert found == []


def test_dc3_with_no_plugin_the_runtime_holds_nothing_on_any_dormant_object(db, admin_engine):
    with db.engine.connect() as conn:
        assert dormant_grants(conn) == NOTHING
        check_runtime(conn)
    with admin_engine.connect() as conn:
        check_dormant(conn, EMPTY_CLAIMS)


# Another function of a dormant name `CLAIM` does not claim, with a signature of its own: a
# reading that ignored signatures would count its EXECUTE as the dormant function's.
OVERLOAD = "execbound.sandbox_notice(text)"


@pytest.mark.usefixtures("revoked_afterwards")
@pytest.mark.parametrize(
    "claim, statements",
    [
        pytest.param(EMPTY_CLAIMS, (), id="nothing"),
        pytest.param(AT_BASE_CLAIM, (), id="what-the-runtime-held-before-0065"),
        pytest.param(
            CLAIM,
            (
                "GRANT EXECUTE ON FUNCTION execbound.agents_sleep(timestamp with time zone) "
                "TO PUBLIC",
                "GRANT SELECT ON execbound.onboarding_invitations TO PUBLIC",
                "GRANT UPDATE (attempts) ON execbound.signup_messages TO PUBLIC",
            ),
            id="public",
        ),
        pytest.param(
            CLAIM,
            (
                "GRANT INSERT, DELETE ON execbound.product_counts TO execbound_app",
                "GRANT SELECT (note) ON execbound.onboarding_invitations TO execbound_app",
                "GRANT EXECUTE ON FUNCTION execbound.sandbox_notice(timestamp with time zone) "
                "TO execbound_app",
            ),
            id="extra-grants",
        ),
        pytest.param(
            CLAIM,
            (
                f"CREATE FUNCTION {OVERLOAD} RETURNS integer LANGUAGE sql AS 'SELECT 1'",
                f"GRANT EXECUTE ON FUNCTION {OVERLOAD} TO execbound_app",
            ),
            id="another-function-of-a-dormant-name",
        ),
    ],
)
def test_dc3_the_runtime_check_reads_the_grants_dormant_grants_reads(
    db, admin_engine, claim, statements
):
    """`check_runtime` reads the dormant tables' grants beside its own function rows and each
    dormant function's EXECUTE from those rows (`_runtime_grants`), where `dormant_grants`
    reads both on its own. Over the runtime's connection, as `check_runtime` runs, the two
    readings are the same in every state here."""
    try:
        with admin_engine.begin() as conn:
            grant_dormant(conn, claim)
            for statement in statements:
                conn.execute(text(statement))
        with db.engine.connect() as conn:
            role = conn.execute(
                text("SELECT oid FROM pg_roles WHERE rolname = current_user")
            ).scalar_one()
            rows = _runtime_rows(conn, role)
            held = dormant_grants(conn)
        assert _runtime_grants(rows) == held
        assert held != NOTHING or claim is EMPTY_CLAIMS
    finally:
        with admin_engine.begin() as conn:
            conn.execute(text(f"DROP FUNCTION IF EXISTS {OVERLOAD}"))


@pytest.mark.usefixtures("revoked_afterwards")
@pytest.mark.parametrize("grant", GRANTS)
def test_dc4_a_dormant_object_nobody_claims_refuses_any_grant(db, admin_engine, grant):
    with admin_engine.begin() as conn:
        conn.execute(text(f"GRANT {grant}"))
    with db.engine.connect() as conn, pytest.raises(DormantGrantsRefused):
        check_runtime(conn)
    with admin_engine.connect() as conn, pytest.raises(DormantGrantsRefused):
        check_dormant(conn, EMPTY_CLAIMS)


@pytest.mark.usefixtures("revoked_afterwards")
def test_dc5_a_claimed_object_holds_exactly_its_claim(db, admin_engine):
    honour_claims(CLAIM)
    # Claimed and not granted: a plugin loaded without its grants.
    with db.engine.connect() as conn, pytest.raises(DormantGrantsRefused):
        check_runtime(conn)
    with admin_engine.begin() as conn:
        grant_dormant(conn, CLAIM)
    with db.engine.connect() as conn:
        check_runtime(conn)
    with admin_engine.connect() as conn:
        check_dormant(conn, CLAIM)
    for extra in (
        "UPDATE (attempts) ON execbound.signup_messages TO execbound_app",
        "INSERT ON execbound.signup_messages TO execbound_app",
        "SELECT ON execbound.product_counts TO execbound_app",
        "EXECUTE ON FUNCTION execbound.agents_sleep(timestamp with time zone) TO PUBLIC",
    ):
        with admin_engine.begin() as conn:
            conn.execute(text(f"GRANT {extra}"))
        with db.engine.connect() as conn, pytest.raises(DormantGrantsRefused):
            check_runtime(conn)
        with admin_engine.begin() as conn:
            grant_dormant(conn, CLAIM)
    with admin_engine.begin() as conn:
        conn.execute(text("REVOKE UPDATE (state) ON execbound.signup_messages FROM execbound_app"))
    with db.engine.connect() as conn, pytest.raises(DormantGrantsRefused):
        check_runtime(conn)


@pytest.mark.usefixtures("revoked_afterwards")
@pytest.mark.parametrize("privilege", ["DELETE", "TRUNCATE"])
def test_dc6_no_claim_lets_the_runtime_delete_or_truncate_a_dormant_table(
    db, admin_engine, privilege
):
    claims = MappingProxyType({"signup_requests": frozenset({"SELECT"})})
    honour_claims(claims)
    with admin_engine.begin() as conn:
        grant_dormant(conn, claims)
        conn.execute(text(f"GRANT {privilege} ON execbound.signup_requests TO execbound_app"))
    with db.engine.connect() as conn, pytest.raises(UnsafeDatabaseRole, match="table privileges"):
        check_runtime(conn)


@pytest.mark.usefixtures("revoked_afterwards")
def test_dc7_grant_dormant_sets_exactly_the_claim_whatever_the_database_held(admin_engine):
    claim = MappingProxyType(
        {
            "onboarding_invitations": frozenset({"SELECT(note)", "SELECT(tenant_id)"}),
            "signup_messages": frozenset({"SELECT", "UPDATE(state)", "UPDATE(attempts)"}),
            "sandbox_notice": frozenset({"EXECUTE"}),
        }
    )
    with admin_engine.begin() as conn:
        conn.execute(text("GRANT SELECT, UPDATE ON execbound.product_counts TO execbound_app"))
        conn.execute(text("GRANT SELECT ON execbound.onboarding_invitations TO PUBLIC"))
        conn.execute(
            text(
                "GRANT EXECUTE ON FUNCTION execbound.agents_sleep(timestamp with time zone) "
                "TO PUBLIC"
            )
        )
        grant_dormant(conn, claim)
        assert dormant_grants(conn) == expected(claim)
        check_dormant(conn, claim)
        grant_dormant(conn, EMPTY_CLAIMS)
        assert dormant_grants(conn) == NOTHING
        check_dormant(conn, EMPTY_CLAIMS)


@pytest.mark.parametrize(
    "claim",
    [
        {"principals": frozenset({"SELECT"})},
        {"product_count": frozenset({"SELECT"})},
        {"signup_requests": frozenset({"DELETE"})},
        {"onboarding_invitations": frozenset({"SELECT", "SELECT(note)"})},
        {"signup_messages": frozenset({"UPDATE(state) ON execbound.tenants TO public; --"})},
    ],
)
def test_dc7_grant_dormant_refuses_what_no_plugin_could_claim(admin_engine, claim):
    with admin_engine.begin() as conn, pytest.raises(ValueError):
        grant_dormant(conn, claim)


@pytest.mark.usefixtures("revoked_afterwards")
@pytest.mark.parametrize(
    "extra",
    [
        f"EXECUTE ON FUNCTION {PRODUCT_COUNT} TO PUBLIC",
        f"EXECUTE ON FUNCTION {PRODUCT_COUNT} TO execbound_app WITH GRANT OPTION",
        "SELECT ON execbound.signup_messages TO PUBLIC",
        "UPDATE (state) ON execbound.signup_messages TO PUBLIC",
        "SELECT ON execbound.signup_messages TO execbound_app WITH GRANT OPTION",
    ],
)
def test_dc7_check_dormant_reads_every_acl_entry_not_only_what_the_runtime_can_do(
    admin_engine, extra
):
    """`dormant_grants` asks what the runtime role can do, which folds PUBLIC's grants into its
    own; the owner-side check reads the ACLs themselves, so a claimed privilege granted to
    PUBLIC as well, or held with a grant option, is refused although the runtime's reach is
    exactly the claim."""
    with admin_engine.begin() as conn:
        grant_dormant(conn, CLAIM)
        conn.execute(text(f"GRANT {extra}"))
        assert dormant_grants(conn) == expected(CLAIM)
        with pytest.raises(DormantGrantsRefused, match="Unsafe dormant grants"):
            check_dormant(conn, CLAIM)
        # Converges again: the owner's revoke takes each of these away.
        grant_dormant(conn, CLAIM)
        check_dormant(conn, CLAIM)


@pytest.mark.usefixtures("revoked_afterwards")
def test_dc7_check_dormant_refuses_a_grant_on_another_function_of_a_dormant_name(admin_engine):
    """An overload is not the catalogued dormant function, so no claim covers it, and the
    runtime holds nothing on it; the ACL check matches functions by name to see it."""
    try:
        with admin_engine.begin() as conn:
            conn.execute(
                text(
                    "CREATE FUNCTION execbound.product_count(p_event text) RETURNS integer "
                    "LANGUAGE sql AS 'SELECT 1'"
                )
            )
            conn.execute(text("REVOKE ALL ON FUNCTION execbound.product_count(text) FROM PUBLIC"))
            conn.execute(
                text("GRANT EXECUTE ON FUNCTION execbound.product_count(text) TO execbound_app")
            )
            grant_dormant(conn, CLAIM)
            assert dormant_grants(conn) == expected(CLAIM)
            with pytest.raises(DormantGrantsRefused):
                check_dormant(conn, CLAIM)
    finally:
        with admin_engine.begin() as conn:
            conn.execute(text("DROP FUNCTION IF EXISTS execbound.product_count(text)"))


@pytest.mark.usefixtures("revoked_afterwards")
def test_dc21_grant_dormant_revokes_what_a_platform_role_holds(admin_engine, monkeypatch):
    """Supabase adds `anon`, `authenticated` and `service_role`, which no local or CI database
    has, so `grant_dormant`'s revoke from them is run here against a role this test creates
    in their place and drops afterwards."""
    if not can_create_roles(admin_engine):
        pytest.skip("the test owner cannot create a role here")
    role = f"eb_platform_{secrets.token_hex(4)}"
    monkeypatch.setattr("execbound.db._PLATFORM_ROLES", (role,))
    with admin_engine.begin() as conn:
        conn.execute(text(f"CREATE ROLE {role} NOLOGIN"))
    try:
        with admin_engine.begin() as conn:
            conn.execute(text(f"GRANT SELECT ON execbound.product_counts TO {role}"))
            conn.execute(
                text(
                    "GRANT EXECUTE ON FUNCTION execbound.agents_sleep(timestamp with time zone) "
                    f"TO {role}"
                )
            )
            grant_dormant(conn, EMPTY_CLAIMS)
            held = conn.execute(
                text(
                    "SELECT has_table_privilege(:role, 'execbound.product_counts', 'SELECT'), "
                    "has_function_privilege(:role, "
                    "'execbound.agents_sleep(timestamp with time zone)', 'EXECUTE')"
                ),
                {"role": role},
            ).one()
        assert tuple(held) == (False, False)
        # A claimed function granted to the platform role after the claims: the runtime's
        # reach is still exactly the claim, and only the ACL check sees the role.
        with admin_engine.begin() as conn:
            grant_dormant(conn, CLAIM)
            conn.execute(text(f"GRANT EXECUTE ON FUNCTION {PRODUCT_COUNT} TO {role}"))
            assert dormant_grants(conn) == expected(CLAIM)
            with pytest.raises(DormantGrantsRefused):
                check_dormant(conn, CLAIM)
            grant_dormant(conn, CLAIM)
            check_dormant(conn, CLAIM)
    finally:
        with admin_engine.begin() as conn:
            # Takes away anything the role still holds here, so it can be dropped.
            conn.execute(text(f"DROP OWNED BY {role}"))
            conn.execute(text(f"DROP ROLE {role}"))


@pytest.mark.usefixtures("revoked_afterwards")
def test_dc21_a_grant_by_another_grantor_survives_grant_dormant_and_is_refused(admin_engine):
    """The owner's `REVOKE` takes away only what the owner granted. A grant made by a role
    that held a grant option (on Supabase, `postgres` from the dashboard) survives
    `grant_dormant`, and `check_dormant` refuses the database.

    The refusal comes from the grantor role's own entry, the grant option the owner gave it,
    which is a grant to a role other than the runtime's; the grant it made to PUBLIC is
    refused the same way. The check's grantor rule is defence in depth: a grant by any grantor
    but the owner needs a grant option held somewhere, which is refused on its own, so the
    grantor rule cannot be exercised alone."""
    if not can_create_roles(admin_engine):
        pytest.skip("the test owner cannot create a role here")
    role = f"eb_grantor_{secrets.token_hex(4)}"
    with admin_engine.begin() as conn:
        conn.execute(text(f"CREATE ROLE {role} NOLOGIN"))
    try:
        with admin_engine.begin() as conn:
            conn.execute(text(f"GRANT USAGE ON SCHEMA execbound TO {role}"))
            conn.execute(
                text(f"GRANT EXECUTE ON FUNCTION {PRODUCT_COUNT} TO {role} WITH GRANT OPTION")
            )
            conn.execute(text(f"SET LOCAL ROLE {role}"))
            conn.execute(text(f"GRANT EXECUTE ON FUNCTION {PRODUCT_COUNT} TO PUBLIC"))
            conn.execute(text("RESET ROLE"))
            grant_dormant(conn, CLAIM)
            survived = conn.execute(
                text(
                    "SELECT count(*) FROM pg_proc p "
                    "JOIN pg_namespace n ON n.oid = p.pronamespace, aclexplode(p.proacl) a "
                    "WHERE n.nspname = 'execbound' AND p.proname = 'product_count' "
                    "AND pg_get_function_identity_arguments(p.oid) = :arguments "
                    "AND a.grantee = 0 AND a.grantor = CAST(:role AS regrole)"
                ),
                {"arguments": dict(DORMANT_FUNCTIONS)["product_count"], "role": role},
            ).scalar_one()
            assert survived == 1
            assert dormant_grants(conn) == expected(CLAIM)
            with pytest.raises(DormantGrantsRefused):
                check_dormant(conn, CLAIM)
    finally:
        with admin_engine.begin() as conn:
            # Revokes what was granted to the role, and with it what the role granted on.
            conn.execute(text(f"DROP OWNED BY {role}"))
            conn.execute(text(f"DROP ROLE {role}"))


def test_dc8_0065_takes_the_grants_away_and_its_downgrade_gives_back_the_runtimes(admin_engine):
    empty_schema(admin_engine)
    config = alembic_config()
    command.downgrade(config, BASE)
    try:
        with admin_engine.connect() as conn:
            assert dormant_grants(conn) == AT_BASE
            # 0042 never took PUBLIC's EXECUTE off `onboarding_invitation_revoke`; 0065 does,
            # and its downgrade gives back only what the runtime role held.
            assert public_executes(conn) == set()
        command.upgrade(config, "0065_dormant_grants")
        with admin_engine.connect() as conn:
            assert dormant_grants(conn) == NOTHING
            assert public_executes(conn) == set()
            check_dormant(conn, EMPTY_CLAIMS)
    finally:
        command.upgrade(config, "head")


def test_dc9_a_callers_connection_owns_the_migrations_transaction(admin_engine):
    """`migrations/env.py` runs every pending migration in a connection a caller passes, inside
    the transaction the caller began, and commits nothing itself (Alembic's shared-connection
    recipe): a caller that rolls back leaves no migration applied."""
    empty_schema(admin_engine)
    config = alembic_config()
    command.downgrade(config, BASE)
    try:
        with admin_engine.connect() as connection:
            transaction = connection.begin()
            shared = Config("alembic.ini")
            shared.attributes["connection"] = connection
            command.upgrade(shared, "head")
            assert (
                connection.execute(
                    text("SELECT version_num FROM execbound.alembic_version")
                ).scalar_one()
                == SCHEMA_REVISION
            )
            transaction.rollback()
        assert revision_of(admin_engine) == BASE
    finally:
        command.upgrade(config, "head")


def schema_state(engine):
    """The revision, every column, every function body and the dormant grants: what a
    transaction that rolled back must leave exactly as it found it."""
    with engine.connect() as conn:
        return (
            conn.execute(text("SELECT version_num FROM execbound.alembic_version")).scalar_one(),
            conn.execute(
                text(
                    "SELECT string_agg(table_name || '.' || column_name, ',' "
                    "ORDER BY table_name, column_name) FROM information_schema.columns "
                    "WHERE table_schema = 'execbound'"
                )
            ).scalar_one(),
            conn.execute(
                text(
                    "SELECT string_agg(md5(pg_get_functiondef(p.oid)), ',' "
                    "ORDER BY p.proname, pg_get_function_identity_arguments(p.oid)) "
                    "FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
                    "WHERE n.nspname = 'execbound'"
                )
            ).scalar_one(),
            dormant_grants(conn),
        )
