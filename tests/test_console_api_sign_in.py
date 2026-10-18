# SPDX-License-Identifier: AGPL-3.0-only
"""`/api/console/v1/tenant/sign-in`: the tenant's own identity provider through the console API.

The directory is scripted in process, so registering here validates a real discovery document
and reaches no network. What these tests are about is the route: who may call it, what a refusal
says, and that nothing a response carries could be used against the customer's directory.
"""

import secrets
from datetime import timedelta
from uuid import UUID

import pytest
from console_api_fixtures import (
    API,
    ORIGIN,
    assert_no_secrets,
    console_client,
    console_config,
    refusals,
)
from idp_fixtures import (
    CLIENT_ID,
    CLIENT_SECRET,
    HOST,
    ISSUER,
    NAME,
    SUBJECT,
    USERNAME,
    StandIn,
    directory_key,
    discovery_document,
)
from test_console_api_step_up import stale, step
from test_execution import world as world
from test_runtime import connector as connector
from test_runtime import live_provider as live_provider
from test_runtime import registry as registry
from test_runtime import runtime as runtime

from execbound import directory_store as store
from execbound import mfa
from execbound.directory import DirectoryAccount, DirectoryConfig
from execbound.envelope import KEY_BYTES, KeyRing
from execbound.surfaces.sessions import load_session

pytestmark = pytest.mark.integration

SIGN_IN = API + "/tenant/sign-in"
RING = KeyRing("dir-v1", {"dir-v1": b"\x33" * KEY_BYTES})
ZERO = "00000000-0000-0000-0000-000000000000"
MFA = KeyRing("test", {"test": b"m" * 32})
VERIFY = API + "/session/verify"


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


def registration(**changes):
    body = {
        "name": "Contoso",
        "issuer": ISSUER,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "subject_claim": "oid",
    }
    body.update(changes)
    return body


@pytest.fixture
def admin(db, runtime, admin_engine, world, config):
    with console_client(db, runtime, admin_engine, world["admin"], config=config) as made:
        yield made


def test_every_route_refuses_a_bearer_and_no_session(db, runtime, seeded, admin_engine, world):
    for path, method in (
        (SIGN_IN, "GET"),
        (SIGN_IN, "POST"),
        (f"{SIGN_IN}/{ZERO}/state", "POST"),
    ):
        results = refusals(db, runtime, seeded, admin_engine, world, path, method)
        assert results["bearer"].status_code == 403
        assert results["bearer"].json()["code"] == "FORBIDDEN"
        assert results["no_session"].status_code == 401


def test_an_approver_is_refused_on_every_route(db, runtime, admin_engine, world, config):
    with console_client(db, runtime, admin_engine, world["human"], config=config) as approver:
        for path, method, body in (
            (SIGN_IN, "GET", None),
            (SIGN_IN, "POST", registration()),
            (f"{SIGN_IN}/{ZERO}/state", "POST", {"state": "enabled"}),
        ):
            answer = approver.get(path) if method == "GET" else approver.post(path, body)
            assert answer.status_code == 403, (path, answer.text)
            assert answer.json()["code"] == "FORBIDDEN"


def test_a_deployment_with_no_key_ring_says_so_and_registers_nothing(
    db, runtime, admin_engine, world
):
    with console_client(db, runtime, admin_engine, world["admin"]) as plain:
        view = plain.get(SIGN_IN)
        assert view.status_code == 200
        assert view.json()["configured"] is False
        assert view.json()["redirect_uri"] is None
        refused = plain.post(SIGN_IN, registration())
        assert refused.status_code in {400, 409, 503}
        assert refused.json()["code"] == "UNAVAILABLE"


def test_the_redirect_uri_is_shown_before_anything_is_registered(admin):
    view = admin.get(SIGN_IN)
    assert view.status_code == 200
    body = view.json()
    assert body["configured"] is True
    assert body["redirect_uri"] == ORIGIN + "/login/directory/callback"
    assert body["invite_url"] == ORIGIN + "/invite"
    assert body["provider"] is None
    assert_no_secrets(view)


def test_a_registration_is_validated_against_the_directory_and_lands_as_a_draft(admin):
    answer = admin.post(SIGN_IN, registration())
    assert answer.status_code == 200, answer.text
    provider = answer.json()["provider"]
    assert provider["state"] == "draft"
    assert provider["issuer"] == ISSUER
    assert provider["subject_claim"] == "oid"
    assert provider["linked"] == 0
    # Nothing in the response is the secret, its ciphertext or its key id.
    assert CLIENT_SECRET not in answer.text
    assert "ciphertext" not in answer.text
    assert_no_secrets(answer)


@pytest.mark.parametrize(
    "changes,field",
    [
        ({"issuer": f"https://{HOST}/common/v2.0"}, "issuer"),
        ({"issuer": "http://login.example/realm"}, "issuer"),
        ({"issuer": "not-a-url"}, "issuer"),
    ],
)
def test_an_issuer_the_server_will_not_register_names_the_field(admin, changes, field):
    answer = admin.post(SIGN_IN, registration(**changes))
    assert answer.status_code == 400
    body = answer.json()
    assert body["code"] == "INVALID_BODY"
    assert body["fields"] == [field]
    # And the directory's own words never reach the browser.
    assert "microsoftonline" not in body["detail"]


def test_an_unreachable_directory_saves_nothing(db, runtime, admin_engine, world, key):
    gone = StandIn(key, unreachable=True)
    with console_client(
        db,
        runtime,
        admin_engine,
        world["admin"],
        config=console_config(directory=DirectoryConfig(RING, ORIGIN, gone.client())),
    ) as admin:
        answer = admin.post(SIGN_IN, registration())
        assert answer.status_code == 400
        assert answer.json()["fields"] == ["issuer"]
        assert admin.get(SIGN_IN).json()["provider"] is None


def test_a_second_provider_is_a_conflict(admin):
    assert admin.post(SIGN_IN, registration()).status_code == 200
    again = admin.post(SIGN_IN, registration())
    assert again.status_code == 409
    assert again.json()["code"] == "CONFLICT"


def test_enabling_a_draft_is_a_conflict_and_verified_is_not_requestable(admin):
    provider = admin.post(SIGN_IN, registration()).json()["provider"]["provider_id"]
    refused = admin.post(f"{SIGN_IN}/{provider}/state", {"state": "enabled"})
    assert refused.status_code == 409
    assert refused.json()["code"] == "CONFLICT"
    unknown = admin.post(f"{SIGN_IN}/{provider}/state", {"state": "verified"})
    assert unknown.status_code == 400
    assert unknown.json()["code"] == "INVALID_BODY"


def test_a_verified_provider_enables_and_then_disables(db, runtime, admin, world, settings):
    provider = admin.post(SIGN_IN, registration()).json()["provider"]["provider_id"]
    store.link_self(
        db,
        world["admin"].tenant_id,
        world["admin"].principal_id,
        UUID(provider),
        DirectoryAccount(SUBJECT, NAME, USERNAME, "refresh"),
        clock=runtime.clock,
    )
    enabled = admin.post(f"{SIGN_IN}/{provider}/state", {"state": "enabled"})
    assert enabled.status_code == 200, enabled.text
    body = enabled.json()
    assert body["provider"]["state"] == "enabled"
    assert body["provider"]["self_linked"] is True
    assert body["sign_in_url"] == f"{ORIGIN}/login/directory/{provider}"
    disabled = admin.post(f"{SIGN_IN}/{provider}/state", {"state": "disabled"})
    assert disabled.status_code == 200
    assert disabled.json()["provider"] is None
    assert disabled.json()["sign_in_url"] is None


def test_a_body_with_an_unknown_field_is_refused_before_anything_is_fetched(admin, stand_in):
    answer = admin.post(SIGN_IN, {**registration(), "scope": "openid"})
    assert answer.status_code == 400
    assert answer.json()["code"] == "INVALID_BODY"
    assert stand_in.seen == []


def test_a_mutation_without_the_token_or_the_origin_is_refused(admin):
    assert admin.post(SIGN_IN, registration(), csrf="wrong").status_code == 403
    assert admin.post(SIGN_IN, registration(), origin=None).status_code == 403


def test_a_provider_id_that_is_not_one_is_not_found(admin):
    assert admin.post(f"{SIGN_IN}/not-a-uuid/state", {"state": "enabled"}).status_code == 404


def test_the_view_never_carries_a_cookie_or_a_secret(admin):
    admin.post(SIGN_IN, registration())
    view = admin.get(SIGN_IN)
    assert_no_secrets(view)
    assert secrets.compare_digest(view.headers.get("cache-control", ""), "no-store")
    assert discovery_document()["token_endpoint"] not in view.text


def test_registering_or_switching_a_provider_asks_for_a_recent_factor(
    db, runtime, admin_engine, world, settings
):
    """Which directory may sign people in is one of the changes the step-up guards
    (THREAT_MODEL.md T4.48). An administrator whose factor was verified more than thirty minutes
    ago registers nothing and switches nothing until they verify again, as for people, access
    and credentials. Both refusals come before the route reads its body or the directory."""
    tenant = world["admin"].tenant_id
    with console_client(
        db,
        runtime,
        admin_engine,
        world["admin"],
        config=console_config(directory=settings, mfa=MFA),
    ) as client:
        session = load_session(db, client.client.cookies.get("eb_session"), clock=runtime.clock)
        seed = mfa.begin_enrollment(db, session, MFA, clock=runtime.clock)
        mfa.confirm_enrollment(db, session, MFA, mfa.totp(seed, step(runtime)), clock=runtime.clock)
        stale(admin_engine, tenant, session.session_id)
        runtime.clock.value += timedelta(seconds=30)

        refused = client.post(SIGN_IN, registration())
        assert refused.status_code == 401 and refused.json()["code"] == "MFA_REQUIRED"
        assert client.get(SIGN_IN).json()["provider"] is None

        # The same registration goes through once a code is verified, so the refusal above was
        # the step-up and nothing else.
        verified = client.post(VERIFY, {"code": mfa.totp(seed, step(runtime))})
        assert verified.status_code == 200, verified.text
        client.csrf = verified.json()["csrf_token"]
        registered = client.post(SIGN_IN, registration())
        assert registered.status_code == 200, registered.text
        provider = registered.json()["provider"]["provider_id"]

        session = load_session(db, client.client.cookies.get("eb_session"), clock=runtime.clock)
        stale(admin_engine, tenant, session.session_id)
        switched = client.post(f"{SIGN_IN}/{provider}/state", {"state": "enabled"})
        assert switched.status_code == 401 and switched.json()["code"] == "MFA_REQUIRED"
        assert client.get(SIGN_IN).json()["provider"]["state"] == "draft"
