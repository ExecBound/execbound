# SPDX-License-Identifier: AGPL-3.0-only
"""A person's own directory identity on My account, and linking it themselves (#253, #241).

`GET /api/console/v1/settings` carries a `directory` block: the tenant's enabled provider,
offered so the person can link their own account, and the person's own active link, or null.
Nothing in it is anybody else's, and a provider that is a draft, verified but not enabled,
disabled, or another tenant's is never offered.

The self-link itself is `GET /login/directory/{provider_id}/link`. An administrator may start
it through a draft provider, because the first sign-in through a draft is what proves the
registration works and marks it verified; anybody else may start it only through an enabled
provider. `directory_link_self` admits an approver on a draft and would mark it verified, so
the route refuses first and `directory_store.link_self` refuses again before the definer
function runs.

The directory is the scripted `idp_fixtures.StandIn`, so every flow here is real and reaches no
network.
"""

from datetime import timedelta
from urllib.parse import parse_qs, urlsplit
from uuid import UUID, uuid4

import pytest
from console_api_fixtures import API, ORIGIN, assert_no_secrets, console_client, console_config
from idp_fixtures import (
    CLIENT_ID,
    CLIENT_SECRET,
    ISSUER,
    NAME,
    SUBJECT,
    TENANT_ID,
    USERNAME,
    StandIn,
    directory_key,
    discovery_document,
)
from sqlalchemy import text
from test_execution import provision_credential, provision_identity
from test_execution import world as world
from test_runtime import connector as connector
from test_runtime import live_provider as live_provider
from test_runtime import registry as registry
from test_runtime import runtime as runtime
from test_sign_in_surface import landed_at

from execbound import access_control as access
from execbound import directory_store as store
from execbound.directory import DirectoryAccount, DirectoryConfig, Discovery, new_flow
from execbound.envelope import KEY_BYTES, KeyRing
from execbound.identity import authenticate

pytestmark = pytest.mark.integration

RING = KeyRing("dir-v1", {"dir-v1": b"\x44" * KEY_BYTES})
APPROVER_SUBJECT = "77777777-0000-4000-8000-0000000000cc"
APPROVER_NAME = "Sam <b>Lee</b>"
APPROVER_USERNAME = "sam@contoso.example"
SETTINGS = API + "/settings"


@pytest.fixture(scope="module")
def key():
    return directory_key()


@pytest.fixture
def stand_in(key):
    return StandIn(key)


@pytest.fixture
def settings(stand_in):
    return DirectoryConfig(RING, ORIGIN, stand_in.client())


@pytest.fixture
def config(settings):
    return console_config(directory=settings)


def discovery() -> Discovery:
    document = discovery_document()
    return Discovery(
        ISSUER,
        document["authorization_endpoint"],
        document["token_endpoint"],
        document["jwks_uri"],
        TENANT_ID,
    )


def registered(db, runtime, settings, tenant: UUID, admin: UUID) -> UUID:
    """A draft: registered by an administrator, signed in through by nobody."""
    return store.register(
        db,
        settings,
        tenant,
        admin,
        name="Contoso",
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        subject_claim="oid",
        discovery=discovery(),
        clock=runtime.clock,
    )


def verified(db, runtime, settings, world) -> UUID:
    """The administrator's test sign-in linked them and marked the draft verified."""
    admin = world["admin"]
    provider = registered(db, runtime, settings, admin.tenant_id, admin.principal_id)
    store.link_self(
        db,
        admin.tenant_id,
        admin.principal_id,
        provider,
        DirectoryAccount(SUBJECT, NAME, USERNAME, "refresh"),
        clock=runtime.clock,
    )
    return provider


def enabled(db, runtime, settings, world) -> UUID:
    admin = world["admin"]
    provider = verified(db, runtime, settings, world)
    store.set_state(
        db, admin.tenant_id, admin.principal_id, provider, "enabled", clock=runtime.clock
    )
    return provider


def state_of(admin_engine, provider: UUID) -> str:
    with admin_engine.connect() as conn:
        return str(
            conn.execute(
                text("SELECT state FROM execbound.identity_providers WHERE provider_id = :p"),
                {"p": provider},
            ).scalar_one()
        )


def links_of(admin_engine, tenant: UUID, principal: UUID) -> int:
    with admin_engine.connect() as conn:
        return int(
            conn.execute(
                text(
                    "SELECT count(*) FROM execbound.identity_links "
                    "WHERE tenant_id = :t AND principal_id = :p"
                ),
                {"t": tenant, "p": principal},
            ).scalar_one()
        )


def linked_events(admin_engine, tenant: UUID) -> int:
    with admin_engine.connect() as conn:
        return int(
            conn.execute(
                text(
                    "SELECT count(*) FROM execbound.audit_events "
                    "WHERE tenant_id = :t AND kind = 'identity.linked'"
                ),
                {"t": tenant},
            ).scalar_one()
        )


def directory_view(person) -> dict:
    answer = person.get(SETTINGS)
    assert answer.status_code == 200, answer.text
    assert_no_secrets(answer)
    return answer.json()["directory"]


def complete(client, started, stand_in, subject: str):
    """The directory's redirect back, for the flow the start put in the browser's cookie."""
    query = parse_qs(urlsplit(started.headers["location"]).query)
    stand_in.nonce = query["nonce"][0]
    stand_in.claim_changes = {
        "oid": subject,
        "name": APPROVER_NAME,
        "preferred_username": APPROVER_USERNAME,
    }
    return client.get(
        "/login/directory/callback", params={"code": "the-code", "state": query["state"][0]}
    )


def flow_cookies(answer) -> list[str]:
    return [c for c in answer.headers.get_list("set-cookie") if c.startswith("eb_dirflow=")]


# ---- the settings view --------------------------------------------------------------------


def test_an_approver_with_no_link_is_offered_the_enabled_provider_and_nothing_else(
    db, runtime, admin_engine, world, settings, config
):
    provider = enabled(db, runtime, settings, world)
    with console_client(db, runtime, admin_engine, world["human"], config=config) as approver:
        view = directory_view(approver)
    assert view == {
        "provider": {"provider_id": str(provider), "name": "Contoso", "state": "enabled"},
        "link": None,
    }


def test_a_linked_person_sees_their_own_link_and_never_anybody_elses(
    db, runtime, admin_engine, world, settings, config
):
    """The administrator linked themselves through the draft; the approver links through the
    enabled provider and signs in once. Each sees their own subject, how it was linked, the
    display hints the directory reported and the last sign-in, and nothing of the other's."""
    provider = enabled(db, runtime, settings, world)
    approver_identity = world["human"]
    store.link_self(
        db,
        approver_identity.tenant_id,
        approver_identity.principal_id,
        provider,
        DirectoryAccount(APPROVER_SUBJECT, APPROVER_NAME, APPROVER_USERNAME, "refresh"),
        clock=runtime.clock,
    )
    row = store.locate_provider(db, provider)
    assert row is not None
    store.sign_in(
        db,
        settings,
        row,
        DirectoryAccount(APPROVER_SUBJECT, APPROVER_NAME, APPROVER_USERNAME, "refresh"),
        clock=runtime.clock,
    )
    with console_client(db, runtime, admin_engine, approver_identity, config=config) as approver:
        view = directory_view(approver)
    link = view["link"]
    assert view["provider"]["provider_id"] == str(provider)
    assert link["provider_id"] == str(provider)
    assert link["provider_name"] == "Contoso"
    assert link["subject"] == APPROVER_SUBJECT
    assert link["via"] == "self"
    # The hints are the directory's text, returned as text: the page renders them inertly.
    assert link["display_name"] == APPROVER_NAME
    assert link["display_username"] == APPROVER_USERNAME
    assert link["created_at"] is not None
    assert link["last_sign_in_at"] is not None
    assert SUBJECT not in str(view) and NAME not in str(view) and USERNAME not in str(view)

    with console_client(db, runtime, admin_engine, world["admin"], config=config) as admin:
        mine = directory_view(admin)
    assert mine["link"]["subject"] == SUBJECT
    assert mine["link"]["via"] == "self"
    assert mine["link"]["display_name"] == NAME
    assert mine["link"]["last_sign_in_at"] is None
    assert APPROVER_SUBJECT not in str(mine) and APPROVER_USERNAME not in str(mine)


def test_a_link_an_administrator_made_says_so(db, runtime, admin_engine, world, settings, config):
    provider = enabled(db, runtime, settings, world)
    store.link_person(
        db,
        world["admin"].tenant_id,
        world["admin"].principal_id,
        world["human"].principal_id,
        provider,
        APPROVER_SUBJECT,
        clock=runtime.clock,
    )
    with console_client(db, runtime, admin_engine, world["human"], config=config) as approver:
        link = directory_view(approver)["link"]
    assert link["via"] == "admin"
    assert link["subject"] == APPROVER_SUBJECT
    assert link["last_sign_in_at"] is None


@pytest.mark.parametrize("state", ["draft", "verified", "disabled"])
def test_a_provider_that_is_not_enabled_is_never_offered(
    db, runtime, admin_engine, world, settings, config, state
):
    if state == "draft":
        registered(db, runtime, settings, world["admin"].tenant_id, world["admin"].principal_id)
    elif state == "verified":
        verified(db, runtime, settings, world)
    else:
        provider = enabled(db, runtime, settings, world)
        store.set_state(
            db,
            world["admin"].tenant_id,
            world["admin"].principal_id,
            provider,
            "disabled",
            clock=runtime.clock,
        )
    with console_client(db, runtime, admin_engine, world["human"], config=config) as approver:
        assert directory_view(approver) == {"provider": None, "link": None}
    with console_client(db, runtime, admin_engine, world["admin"], config=config) as admin:
        assert directory_view(admin)["provider"] is None


def test_another_tenants_enabled_provider_is_invisible(
    db, runtime, admin_engine, world, settings, config, seeded
):
    other = seeded["tenants"][1]
    assert other != world["admin"].tenant_id
    stranger = uuid4()
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.principals(tenant_id, principal_id, kind, active, space_id)"
                " VALUES (:t, :p, 'ADMIN', true, NULL)"
            ),
            {"t": other, "p": stranger},
        )
    provider = registered(db, runtime, settings, other, stranger)
    store.link_self(
        db,
        other,
        stranger,
        provider,
        DirectoryAccount(SUBJECT, NAME, USERNAME, "refresh"),
        clock=runtime.clock,
    )
    store.set_state(db, other, stranger, provider, "enabled", clock=runtime.clock)
    with console_client(db, runtime, admin_engine, world["human"], config=config) as approver:
        assert directory_view(approver) == {"provider": None, "link": None}


def test_a_deployment_with_no_key_ring_offers_no_link_but_shows_the_one_there_is(
    db, runtime, admin_engine, world, settings
):
    """Without the ring every directory route answers 404, so a button would lead nowhere."""
    enabled(db, runtime, settings, world)
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        view = directory_view(admin)
    assert view["provider"] is None
    assert view["link"]["subject"] == SUBJECT


# ---- linking one's own identity -----------------------------------------------------------


def test_an_approver_links_their_own_identity_through_the_enabled_provider(
    db, runtime, admin_engine, world, settings, config, stand_in
):
    provider = enabled(db, runtime, settings, world)
    approver_identity = world["human"]
    with console_client(db, runtime, admin_engine, approver_identity, config=config) as approver:
        started = approver.client.get(f"/login/directory/{provider}/link")
        assert started.status_code == 303, started.text
        assert started.headers["location"].startswith(
            discovery_document()["authorization_endpoint"]
        )
        assert len(flow_cookies(started)) == 1
        back = complete(approver.client, started, stand_in, APPROVER_SUBJECT)
        # An approver lands on their own settings, where the card now shows the link.
        assert landed_at(back, session=False) == "/settings"
        view = directory_view(approver)
    assert view["link"]["via"] == "self"
    assert view["link"]["subject"] == APPROVER_SUBJECT
    assert view["link"]["display_name"] == APPROVER_NAME
    assert store.locate_link(db, provider, APPROVER_SUBJECT) == (
        approver_identity.tenant_id,
        approver_identity.principal_id,
    )
    assert state_of(admin_engine, provider) == "enabled"


@pytest.mark.parametrize("state", ["draft", "verified"])
def test_an_approver_cannot_start_a_link_through_a_provider_that_is_not_enabled(
    db, runtime, admin_engine, world, settings, config, stand_in, state, monkeypatch
):
    """The regression: before this, the route checked the tenant alone, so an approver's
    sign-in through a draft linked them and marked the provider verified, evidence the
    tenant's administrator never produced.

    The session's kind refuses an approver on its own, so the route does not ask the database
    whether they configure the provider."""
    admin = world["admin"]
    provider = (
        registered(db, runtime, settings, admin.tenant_id, admin.principal_id)
        if state == "draft"
        else verified(db, runtime, settings, world)
    )
    approver_identity = world["human"]
    events = linked_events(admin_engine, admin.tenant_id)

    def asked(*_args, **_kwargs):
        raise AssertionError("the route asked whether an approver configures the provider")

    with console_client(db, runtime, admin_engine, approver_identity, config=config) as approver:
        monkeypatch.setattr(store, "configures", asked)
        started = approver.client.get(f"/login/directory/{provider}/link")
        assert started.status_code == 404, started.headers.get("location")
        assert flow_cookies(started) == []
    assert state_of(admin_engine, provider) == state
    assert links_of(admin_engine, admin.tenant_id, approver_identity.principal_id) == 0
    assert linked_events(admin_engine, admin.tenant_id) == events


def test_a_flow_minted_for_an_approver_on_a_draft_cannot_verify_it(
    db, runtime, admin_engine, world, settings, config, stand_in
):
    """The callback holds no session, so who is linking comes from the sealed flow cookie. A
    flow minted before the route refused, or by any other path, still binds nobody: the store
    refuses a non-administrator on a provider that is not enabled before the definer runs."""
    admin = world["admin"]
    provider = registered(db, runtime, settings, admin.tenant_id, admin.principal_id)
    approver_identity = world["human"]
    flow = new_flow(str(provider), link_principal=str(approver_identity.principal_id))
    with console_client(db, runtime, admin_engine, approver_identity, config=config) as approver:
        approver.client.cookies.set("eb_dirflow", settings.seal_flow(flow))
        stand_in.nonce = flow.nonce
        stand_in.claim_changes = {"oid": APPROVER_SUBJECT}
        back = approver.client.get(
            "/login/directory/callback", params={"code": "the-code", "state": flow.state}
        )
    assert back.status_code == 403
    assert "That account cannot sign in here." in back.text
    assert state_of(admin_engine, provider) == "draft"
    assert links_of(admin_engine, admin.tenant_id, approver_identity.principal_id) == 0


def test_link_self_refuses_a_non_administrator_on_a_draft_and_writes_nothing(
    db, runtime, admin_engine, world, settings
):
    admin = world["admin"]
    provider = registered(db, runtime, settings, admin.tenant_id, admin.principal_id)
    events = linked_events(admin_engine, admin.tenant_id)
    with pytest.raises(store.DirectoryError) as refused:
        store.link_self(
            db,
            admin.tenant_id,
            world["human"].principal_id,
            provider,
            DirectoryAccount(APPROVER_SUBJECT, APPROVER_NAME, APPROVER_USERNAME, "refresh"),
            clock=runtime.clock,
        )
    assert refused.value.code == "INVALID_PROVIDER"
    assert state_of(admin_engine, provider) == "draft"
    assert links_of(admin_engine, admin.tenant_id, world["human"].principal_id) == 0
    assert linked_events(admin_engine, admin.tenant_id) == events


def test_a_person_made_an_administrator_through_a_role_may_verify_a_draft(
    db, runtime, admin_engine, world, settings
):
    """Who is an administrator is the effective kind, a role granted on the access page, not
    the principal row's original kind: a promoted approver's row still says HUMAN_APPROVER."""
    admin = world["admin"]
    promoted = world["human"]
    with db.transaction(admin.tenant_id) as conn:
        access.set_roles_in(
            conn,
            admin.tenant_id,
            admin.principal_id,
            "user",
            promoted.principal_id,
            [{"role": "administrator", "space_id": None}],
            "Test access change",
        )
    provider = registered(db, runtime, settings, admin.tenant_id, admin.principal_id)
    linked = store.link_self(
        db,
        admin.tenant_id,
        promoted.principal_id,
        provider,
        DirectoryAccount(APPROVER_SUBJECT, APPROVER_NAME, APPROVER_USERNAME, "refresh"),
        clock=runtime.clock,
    )
    assert linked["verified"] is True
    # The kind the callback lands by is the effective one too, not the row's HUMAN_APPROVER.
    assert linked["kind"] == "ADMIN"
    assert state_of(admin_engine, provider) == "verified"


def granted(db, world, subject, role: str) -> None:
    """One workspace-wide role for a person, granted on the access page by the administrator."""
    admin = world["admin"]
    with db.transaction(admin.tenant_id) as conn:
        access.set_roles_in(
            conn,
            admin.tenant_id,
            admin.principal_id,
            "user",
            subject.principal_id,
            [{"role": role, "space_id": None}],
            "Test access change",
        )


def signed_in_afresh(db, runtime, admin_engine, person):
    """A new credential for a person whose earlier ones a promotion revoked (0047)."""
    with admin_engine.begin() as conn:
        token = provision_credential(
            conn, person.tenant_id, person.principal_id, runtime.clock.now(), timedelta(hours=2)
        )
    return authenticate(db, token)


def test_a_person_made_an_administrator_through_a_role_lands_on_workspace_settings(
    db, runtime, admin_engine, world, settings, config, stand_in
):
    """The callback lands a self-link by the kind `link_self` answers, which was the principal
    row's own: a person made an administrator on the access page, whose row still says
    HUMAN_APPROVER, was sent to My account after the test sign-in that verified the draft,
    where every other administrator is sent to Workspace settings. An administrator role is
    never granted for one space (`INVALID_ROLE_SCOPE`), so this person is a workspace
    administrator and never one narrowed to spaces."""
    admin = world["admin"]
    granted(db, world, world["human"], "administrator")
    promoted = signed_in_afresh(db, runtime, admin_engine, world["human"])
    assert promoted.kind == "ADMIN"
    provider = registered(db, runtime, settings, admin.tenant_id, admin.principal_id)
    with console_client(db, runtime, admin_engine, promoted, config=config) as person:
        started = person.client.get(f"/login/directory/{provider}/link")
        assert started.status_code == 303, started.text
        back = complete(person.client, started, stand_in, APPROVER_SUBJECT)
        assert landed_at(back, session=False) == "/tenant"
        # The page they land on is one their session reads.
        assert person.get(API + "/tenant").status_code == 200
    assert state_of(admin_engine, provider) == "verified"
    assert links_of(admin_engine, admin.tenant_id, promoted.principal_id) == 1


def test_an_administrator_left_only_an_approver_role_lands_on_my_account(
    db, runtime, admin_engine, world, settings, config, stand_in
):
    """The other direction: a principal created as an administrator and then given only the
    approver role on the access page is an approver, so the self-link through the enabled
    provider lands them on My account, not on Workspace settings, which refuses them."""
    admin = world["admin"]
    provider = enabled(db, runtime, settings, world)
    former = provision_identity(admin_engine, db, admin.tenant_id, "ADMIN", runtime.clock.now())
    granted(db, world, former, "approver")
    with console_client(db, runtime, admin_engine, former, config=config) as person:
        assert person.get(API + "/tenant").status_code == 403
        started = person.client.get(f"/login/directory/{provider}/link")
        assert started.status_code == 303, started.text
        back = complete(person.client, started, stand_in, APPROVER_SUBJECT)
        assert landed_at(back, session=False) == "/settings"
        assert person.get(SETTINGS).status_code == 200
    assert state_of(admin_engine, provider) == "enabled"
    assert links_of(admin_engine, admin.tenant_id, former.principal_id) == 1


def test_an_administrator_still_tests_a_draft_through_the_link_route(
    db, runtime, admin_engine, world, settings, config, stand_in
):
    """The hardening is about who, not about drafts: the registering administrator's test
    sign-in is what verifies a provider, and it still does."""
    admin_identity = world["admin"]
    provider = registered(
        db, runtime, settings, admin_identity.tenant_id, admin_identity.principal_id
    )
    with console_client(db, runtime, admin_engine, admin_identity, config=config) as admin:
        started = admin.client.get(f"/login/directory/{provider}/link")
        assert started.status_code == 303, started.text
        back = complete(admin.client, started, stand_in, SUBJECT)
        assert landed_at(back, session=False) == "/tenant"
    assert state_of(admin_engine, provider) == "verified"
    assert links_of(admin_engine, admin_identity.tenant_id, admin_identity.principal_id) == 1
