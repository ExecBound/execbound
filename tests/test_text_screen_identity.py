# SPDX-License-Identifier: AGPL-3.0-only
"""Text the identity provider supplies, withheld rather than refused where it is shaped like a
secret (T7.7): directory subjects (`directory_store.link_self`, `link_person` and
`sign_in`), a Google subject (`user_accounts.provider_sign_in`), the identity-linking write
`passwords.bind_identity` shares with them (found by grepping every `append_event` whose kind
is `identity.linked` or `human_sign_in.*`), and the issuer a registration's
discovery document confirms (`directory_store.register`) — the administrator types it, but it
reaches the event only because the provider's own discovery document echoed it back, which
makes it provider-confirmed text exactly like a subject, not something a person typed freely.

Refusing any of these would lock a person out of a sign-in they already proved, stop an account
being linked at all, or stop a provider being registered at all, so each boundary keeps working
exactly as before and the event carries `WITHHELD` beside a SHA-256 digest instead of the
value, which correlates events about the same person or provider without carrying it. The link
table and the provider row hold the real value exactly as they do today, so a later sign-in
with the same subject still finds the same person. A plain value is written exactly as it is
today, with no `_digest` key at all.

None of these paths folds a subject to lowercase (`directory.subject_of` and `oidc.py`'s own
check both read the claim exactly as given), so the uppercase samples below keep the shapes
their patterns need: `STRIPE`'s `sk_live_` prefix and `JWT`'s case-sensitive `eyJ`. Each sample
is checked against the field's own validator first (one to 255 characters, nothing else, for a
subject; a well-formed `https` URL with no credentials, query or fragment, for an issuer), so a
sample the field itself would reject could never pass for nothing.
"""

from hashlib import sha256
from urllib.parse import urlsplit

import pytest
from idp_fixtures import (
    CLIENT_ID,
    CLIENT_SECRET,
    SUBJECT,
    StandIn,
    directory_key,
    discovery_document,
)
from secret_shapes import AGENT_TOKEN, JWT, LOWER_STRIPE, STRIPE
from sqlalchemy import text
from test_directory_store import ANOTHER_SUBJECT, account, enabled, registered
from test_directory_store import cast as cast
from test_directory_store import clock as clock
from test_directory_store import settings as settings
from test_workspace_accounts import adopt, enroll
from text_screen_helpers import assert_nothing_found, kind_count

from execbound import directory_store as store
from execbound.directory import discover, normalize_issuer
from execbound.passwords import bind_identity
from execbound.resolution.models import SystemClock
from execbound.secrets import secret_shaped
from execbound.signin import ExternalAccount
from execbound.user_accounts import provider_sign_in

pytestmark = pytest.mark.integration

LINKED_KIND = "identity.linked"
DIRECTORY_SIGN_IN_KIND = "human_sign_in.directory"
GOOGLE_SIGN_IN_KIND = "human_sign_in.google"
REGISTERED_KIND = "identity_provider.registered"

# Every plain-control test asserts its payload holds exactly one of these key sets, read
# straight from the writer, so "written exactly as before" is the whole payload and not just
# the one field a test happens to look at.
DIRECTORY_LINKED_KEYS = {"principal_id", "provider_id", "subject", "via"}
DIRECTORY_SIGN_IN_KEYS = {"credential_id", "kind", "provider_id", "subject", "expires_at"}
BIND_IDENTITY_LINKED_KEYS = {"provider", "subject"}
GOOGLE_SIGN_IN_KEYS = {"credential_id", "kind", "expires_at", "subject"}
REGISTERED_KEYS = {"provider_id", "issuer", "subject_claim"}

SAMPLES = [STRIPE, JWT, AGENT_TOKEN]
SAMPLE_IDS = ["stripe", "jwt", "agent-token"]

# A Google `sub` is a large numeric string; this one is synthetic and identifies nobody.
PLAIN_GOOGLE_SUBJECT = "117322412345678901234"

# A realm issuer whose realm name is shaped like a Stripe key; `normalize_issuer` keeps the
# path as given.
SHAPED_ISSUER = "https://kc.example.test/realms/" + LOWER_STRIPE
PLAIN_ISSUER = "https://kc.example.test/realms/contoso"


def _subject_validates(subject: str) -> None:
    """The one check every subject field here makes, `directory.subject_of`'s and `oidc.py`'s
    own validator alike: one to 255 characters, read exactly as given. A sample that failed
    this would be refused for a reason that has nothing to do with this screen."""
    assert 0 < len(subject) <= 255


def _payload(engine, tenant, kind):
    """The latest event of this kind."""
    with engine.begin() as conn:
        return conn.execute(
            text(
                "SELECT payload FROM execbound.audit_events "
                "WHERE tenant_id = :t AND kind = :k ORDER BY sequence DESC LIMIT 1"
            ),
            {"t": tenant, "k": kind},
        ).scalar_one()


def _assert_withheld(payload, field, value, keys):
    """The field is withheld beside its digest, and the payload carries exactly ``keys`` plus
    that one digest key: withholding adds one key and changes nothing else."""
    assert payload[field] == "WITHHELD"
    assert payload[f"{field}_digest"] == sha256(value.encode()).hexdigest()
    assert set(payload) == keys | {f"{field}_digest"}


def _assert_plain(payload, field, value, keys):
    """The field holds the plain value, and the payload carries exactly ``keys``, the same keys
    the writer carried before withholding existed, and no digest."""
    assert payload[field] == value
    assert set(payload) == keys


def _stand_in_for(issuer):
    """A discovery document whose issuer and endpoints all sit on ``issuer``'s own host,
    which `directory.discover`'s `_endpoint` requires (`DISCOVERY_FOREIGN_HOST` otherwise)."""
    host = urlsplit(issuer).hostname
    document = discovery_document(
        issuer=issuer,
        authorization_endpoint=f"https://{host}/protocol/openid-connect/auth",
        token_endpoint=f"https://{host}/protocol/openid-connect/token",
        jwks_uri=f"https://{host}/protocol/openid-connect/certs",
    )
    return StandIn(directory_key(), discovery=document)


def _register(db, settings, cast, clock, issuer):
    """Fetch discovery for ``issuer`` through a matching fake directory and register it,
    exactly as the console route's `register` does, returning the new provider's id."""
    discovery = discover(issuer, http=_stand_in_for(issuer).client())
    return store.register(
        db,
        settings,
        cast["tenant"],
        cast["admin"],
        name="Keycloak",
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        subject_claim="oid",
        discovery=discovery,
        clock=clock,
    )


# ---- directory: an administrator's own self link -------------------------------------------


@pytest.mark.parametrize("subject", SAMPLES, ids=SAMPLE_IDS)
def test_a_shaped_subject_self_links_and_is_withheld(
    db, settings, cast, clock, admin_engine, subject
):
    _subject_validates(subject)
    tenant = cast["tenant"]
    provider = registered(db, settings, cast, clock)
    before = kind_count(admin_engine, tenant, LINKED_KIND)
    linked = store.link_self(db, tenant, cast["admin"], provider, account(subject), clock=clock)
    assert linked["verified"] is True
    assert kind_count(admin_engine, tenant, LINKED_KIND) == before + 1
    linked_payload = _payload(admin_engine, tenant, LINKED_KIND)
    _assert_withheld(linked_payload, "subject", subject, DIRECTORY_LINKED_KEYS)
    assert linked_payload["via"] == "self"
    assert_nothing_found(admin_engine, tenant)
    # The link table still holds the real subject, so a sign-in with it finds this person,
    # once the provider the self link verified is also requested enabled.
    store.set_state(db, tenant, cast["admin"], provider, "enabled", clock=clock)
    row = store.locate_provider(db, provider)
    before_signed = kind_count(admin_engine, tenant, DIRECTORY_SIGN_IN_KIND)
    identity = store.sign_in(db, settings, row, account(subject), clock=clock)
    assert identity.principal_id == cast["admin"]
    assert kind_count(admin_engine, tenant, DIRECTORY_SIGN_IN_KIND) == before_signed + 1
    signed_payload = _payload(admin_engine, tenant, DIRECTORY_SIGN_IN_KIND)
    _assert_withheld(signed_payload, "subject", subject, DIRECTORY_SIGN_IN_KEYS)
    assert_nothing_found(admin_engine, tenant)


def test_a_plain_subject_self_links_as_before(db, settings, cast, clock, admin_engine):
    tenant = cast["tenant"]
    provider = registered(db, settings, cast, clock)
    before = kind_count(admin_engine, tenant, LINKED_KIND)
    linked = store.link_self(db, tenant, cast["admin"], provider, account(SUBJECT), clock=clock)
    assert linked["verified"] is True
    assert kind_count(admin_engine, tenant, LINKED_KIND) == before + 1
    linked_payload = _payload(admin_engine, tenant, LINKED_KIND)
    _assert_plain(linked_payload, "subject", SUBJECT, DIRECTORY_LINKED_KEYS)
    assert linked_payload["via"] == "self"
    store.set_state(db, tenant, cast["admin"], provider, "enabled", clock=clock)
    row = store.locate_provider(db, provider)
    before_signed = kind_count(admin_engine, tenant, DIRECTORY_SIGN_IN_KIND)
    identity = store.sign_in(db, settings, row, account(SUBJECT), clock=clock)
    assert identity.principal_id == cast["admin"]
    assert kind_count(admin_engine, tenant, DIRECTORY_SIGN_IN_KIND) == before_signed + 1
    signed_payload = _payload(admin_engine, tenant, DIRECTORY_SIGN_IN_KIND)
    _assert_plain(signed_payload, "subject", SUBJECT, DIRECTORY_SIGN_IN_KEYS)


# ---- directory: the administrator's `link_person` -------------------------------------------


@pytest.mark.parametrize("subject", SAMPLES, ids=SAMPLE_IDS)
def test_a_shaped_subject_is_linked_by_an_administrator_and_withheld(
    db, settings, cast, clock, admin_engine, subject
):
    _subject_validates(subject)
    tenant = cast["tenant"]
    provider = enabled(db, settings, cast, clock)
    before = kind_count(admin_engine, tenant, LINKED_KIND)
    store.link_person(db, tenant, cast["admin"], cast["approver"], provider, subject, clock=clock)
    assert kind_count(admin_engine, tenant, LINKED_KIND) == before + 1
    linked_payload = _payload(admin_engine, tenant, LINKED_KIND)
    _assert_withheld(linked_payload, "subject", subject, DIRECTORY_LINKED_KEYS)
    assert linked_payload["via"] == "admin"
    assert_nothing_found(admin_engine, tenant)
    row = store.locate_provider(db, provider)
    before_signed = kind_count(admin_engine, tenant, DIRECTORY_SIGN_IN_KIND)
    identity = store.sign_in(db, settings, row, account(subject), clock=clock)
    assert identity.principal_id == cast["approver"]
    assert kind_count(admin_engine, tenant, DIRECTORY_SIGN_IN_KIND) == before_signed + 1
    signed_payload = _payload(admin_engine, tenant, DIRECTORY_SIGN_IN_KIND)
    _assert_withheld(signed_payload, "subject", subject, DIRECTORY_SIGN_IN_KEYS)
    assert_nothing_found(admin_engine, tenant)


def test_a_plain_subject_is_linked_by_an_administrator_as_before(
    db, settings, cast, clock, admin_engine
):
    tenant = cast["tenant"]
    provider = enabled(db, settings, cast, clock)
    before = kind_count(admin_engine, tenant, LINKED_KIND)
    store.link_person(
        db, tenant, cast["admin"], cast["approver"], provider, ANOTHER_SUBJECT, clock=clock
    )
    assert kind_count(admin_engine, tenant, LINKED_KIND) == before + 1
    linked_payload = _payload(admin_engine, tenant, LINKED_KIND)
    _assert_plain(linked_payload, "subject", ANOTHER_SUBJECT, DIRECTORY_LINKED_KEYS)
    assert linked_payload["via"] == "admin"
    row = store.locate_provider(db, provider)
    before_signed = kind_count(admin_engine, tenant, DIRECTORY_SIGN_IN_KIND)
    identity = store.sign_in(db, settings, row, account(ANOTHER_SUBJECT), clock=clock)
    assert identity.principal_id == cast["approver"]
    assert kind_count(admin_engine, tenant, DIRECTORY_SIGN_IN_KIND) == before_signed + 1
    signed_payload = _payload(admin_engine, tenant, DIRECTORY_SIGN_IN_KIND)
    _assert_plain(signed_payload, "subject", ANOTHER_SUBJECT, DIRECTORY_SIGN_IN_KEYS)


# ---- directory: a sign-in that redeems an invitation ------------------------------------------


@pytest.mark.parametrize("subject", SAMPLES, ids=SAMPLE_IDS)
def test_a_shaped_subject_signs_in_through_an_invitation_and_is_withheld(
    db, settings, cast, clock, admin_engine, subject
):
    _subject_validates(subject)
    tenant = cast["tenant"]
    provider = enabled(db, settings, cast, clock)
    minted = store.invite(db, tenant, cast["admin"], cast["approver"], provider)
    invitation, _ = store.check_invitation(db, minted.code)
    row = store.locate_provider(db, provider)
    before_linked = kind_count(admin_engine, tenant, LINKED_KIND)
    before_signed = kind_count(admin_engine, tenant, DIRECTORY_SIGN_IN_KIND)
    identity = store.sign_in(
        db, settings, row, account(subject), invitation_id=invitation, clock=clock
    )
    assert identity.principal_id == cast["approver"]
    assert kind_count(admin_engine, tenant, LINKED_KIND) == before_linked + 1
    assert kind_count(admin_engine, tenant, DIRECTORY_SIGN_IN_KIND) == before_signed + 1
    linked_payload = _payload(admin_engine, tenant, LINKED_KIND)
    _assert_withheld(linked_payload, "subject", subject, DIRECTORY_LINKED_KEYS)
    assert linked_payload["via"] == "invitation"
    signed_payload = _payload(admin_engine, tenant, DIRECTORY_SIGN_IN_KIND)
    _assert_withheld(signed_payload, "subject", subject, DIRECTORY_SIGN_IN_KEYS)
    assert_nothing_found(admin_engine, tenant)
    # No invitation this time: the link the first sign-in created is what finds the person.
    again = store.sign_in(db, settings, row, account(subject), clock=clock)
    assert again.principal_id == cast["approver"]
    assert_nothing_found(admin_engine, tenant)


def test_a_plain_subject_signs_in_through_an_invitation_as_before(
    db, settings, cast, clock, admin_engine
):
    tenant = cast["tenant"]
    provider = enabled(db, settings, cast, clock)
    minted = store.invite(db, tenant, cast["admin"], cast["approver"], provider)
    invitation, _ = store.check_invitation(db, minted.code)
    row = store.locate_provider(db, provider)
    before_linked = kind_count(admin_engine, tenant, LINKED_KIND)
    before_signed = kind_count(admin_engine, tenant, DIRECTORY_SIGN_IN_KIND)
    identity = store.sign_in(
        db, settings, row, account(ANOTHER_SUBJECT), invitation_id=invitation, clock=clock
    )
    assert identity.principal_id == cast["approver"]
    assert kind_count(admin_engine, tenant, LINKED_KIND) == before_linked + 1
    assert kind_count(admin_engine, tenant, DIRECTORY_SIGN_IN_KIND) == before_signed + 1
    linked_payload = _payload(admin_engine, tenant, LINKED_KIND)
    _assert_plain(linked_payload, "subject", ANOTHER_SUBJECT, DIRECTORY_LINKED_KEYS)
    signed_payload = _payload(admin_engine, tenant, DIRECTORY_SIGN_IN_KIND)
    _assert_plain(signed_payload, "subject", ANOTHER_SUBJECT, DIRECTORY_SIGN_IN_KEYS)


# ---- Google: `user_accounts.provider_sign_in`, and the `identity.linked` its binding shares
# with `passwords.bind_identity` ---------------------------------------------------------------


@pytest.mark.parametrize("subject", SAMPLES, ids=SAMPLE_IDS)
def test_a_shaped_google_subject_signs_in_and_is_withheld(db, admin_engine, seeded, subject):
    _subject_validates(subject)
    tenant = seeded["tenants"][0]
    principal, _ = enroll(admin_engine, tenant)
    before_linked = kind_count(admin_engine, tenant, LINKED_KIND)
    bind_identity(
        db,
        tenant,
        principal,
        provider="google",
        subject=subject,
        email="member@example.test",
        display_name=None,
    )
    assert kind_count(admin_engine, tenant, LINKED_KIND) == before_linked + 1
    linked_payload = _payload(admin_engine, tenant, LINKED_KIND)
    _assert_withheld(linked_payload, "subject", subject, BIND_IDENTITY_LINKED_KEYS)
    assert_nothing_found(admin_engine, tenant)
    adopt(db, tenant, principal)
    before_signed = kind_count(admin_engine, tenant, GOOGLE_SIGN_IN_KIND)
    identity = provider_sign_in(
        db, ExternalAccount("google", subject, "member@example.test", None), clock=SystemClock()
    )
    assert identity.principal_id == principal
    assert kind_count(admin_engine, tenant, GOOGLE_SIGN_IN_KIND) == before_signed + 1
    signed_payload = _payload(admin_engine, tenant, GOOGLE_SIGN_IN_KIND)
    _assert_withheld(signed_payload, "subject", subject, GOOGLE_SIGN_IN_KEYS)
    assert_nothing_found(admin_engine, tenant)
    # The link table still holds the real subject, so a second sign-in finds the same person.
    again = provider_sign_in(
        db, ExternalAccount("google", subject, "member@example.test", None), clock=SystemClock()
    )
    assert again.principal_id == principal


def test_a_plain_google_subject_signs_in_as_before(db, admin_engine, seeded):
    tenant = seeded["tenants"][0]
    principal, _ = enroll(admin_engine, tenant)
    before_linked = kind_count(admin_engine, tenant, LINKED_KIND)
    bind_identity(
        db,
        tenant,
        principal,
        provider="google",
        subject=PLAIN_GOOGLE_SUBJECT,
        email="member@example.test",
        display_name=None,
    )
    assert kind_count(admin_engine, tenant, LINKED_KIND) == before_linked + 1
    linked_payload = _payload(admin_engine, tenant, LINKED_KIND)
    _assert_plain(linked_payload, "subject", PLAIN_GOOGLE_SUBJECT, BIND_IDENTITY_LINKED_KEYS)
    adopt(db, tenant, principal)
    before_signed = kind_count(admin_engine, tenant, GOOGLE_SIGN_IN_KIND)
    identity = provider_sign_in(
        db,
        ExternalAccount("google", PLAIN_GOOGLE_SUBJECT, "member@example.test", None),
        clock=SystemClock(),
    )
    assert identity.principal_id == principal
    assert kind_count(admin_engine, tenant, GOOGLE_SIGN_IN_KIND) == before_signed + 1
    signed_payload = _payload(admin_engine, tenant, GOOGLE_SIGN_IN_KIND)
    _assert_plain(signed_payload, "subject", PLAIN_GOOGLE_SUBJECT, GOOGLE_SIGN_IN_KEYS)


# ---- registration: the issuer a provider's own discovery document confirms -------------------


def test_a_shaped_issuer_registers_and_is_withheld(db, settings, cast, clock, admin_engine):
    assert normalize_issuer(SHAPED_ISSUER) == SHAPED_ISSUER
    assert secret_shaped(SHAPED_ISSUER)
    tenant = cast["tenant"]
    before = kind_count(admin_engine, tenant, REGISTERED_KIND)
    provider = _register(db, settings, cast, clock, SHAPED_ISSUER)
    assert kind_count(admin_engine, tenant, REGISTERED_KIND) == before + 1
    payload = _payload(admin_engine, tenant, REGISTERED_KIND)
    _assert_withheld(payload, "issuer", SHAPED_ISSUER, REGISTERED_KEYS)
    assert_nothing_found(admin_engine, tenant)
    # The stored row keeps the real issuer: registration is never refused for its shape.
    row = store.locate_provider(db, provider)
    assert row.issuer == SHAPED_ISSUER


def test_a_plain_issuer_registers_as_before(db, settings, cast, clock, admin_engine):
    tenant = cast["tenant"]
    before = kind_count(admin_engine, tenant, REGISTERED_KIND)
    provider = _register(db, settings, cast, clock, PLAIN_ISSUER)
    assert kind_count(admin_engine, tenant, REGISTERED_KIND) == before + 1
    payload = _payload(admin_engine, tenant, REGISTERED_KIND)
    _assert_plain(payload, "issuer", PLAIN_ISSUER, REGISTERED_KEYS)
    row = store.locate_provider(db, provider)
    assert row.issuer == PLAIN_ISSUER
