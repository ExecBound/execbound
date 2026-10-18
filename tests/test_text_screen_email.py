# SPDX-License-Identifier: AGPL-3.0-only
"""Email addresses a person types, screened for a domain shaped like a secret (T7.7):
`people_pages.set_email`, `administration.invite_person`, `passwords.set_email` and
`invitations.create_invitation`, each refused with the `INVALID_EMAIL` code the field's own
check already uses, quoting nothing and leaving no trace of the write it would have made,
exactly as `tests/test_text_screen_reasons.py` and `tests/test_text_screen_names.py` proved
for other text.

**Only the domain is screened, never the local part.** The whole address never reaches an
event: `person.email_set` carries `domain`, and `invitation.created` carries `email_domain`
(the full address goes only to non-event places, such as the stored `principals.email` row
and the invitation's own delivery, neither of which is screened). The rule is to screen
exactly the values an event carries, so every screen here is
``secret_shaped(normalized.rsplit("@", 1)[1])``, never ``secret_shaped(normalized)``: a
secret-shaped local part behind an ordinary domain is still accepted everywhere, which
`test_the_accepted_local_part_sample_passes_and_its_domain_is_not_shaped` establishes once and
the per-writer accepted controls (`ACCEPTED_SHAPED_LOCAL_PART`, one per `normalize_email`
writer plus `test_a_shaped_local_part_invitation_is_still_accepted_when_the_domain_is_not` for
`create_invitation`) each exercise; only a secret-shaped domain is ever refused.

`normalize_email` admits only three of `secret_shapes.FREE_TEXT`'s shapes as an address at
all: BEARER and the embedded-Stripe-key sentence both carry a space, which the address
grammar forbids outright, and DATABASE_URL carries a second ``@``, which the grammar forbids
just as absolutely. None of the three is ever a valid address for any writer here to see, so
none is ever a domain-screen sample (`test_most_free_text_samples_are_not_addresses_at_all`
writes that down). JWT does parse as a domain, but its shape only matches case-sensitively and
`normalize_email` lowercases, so a JWT-shaped domain is no longer a finding once normalized
(`test_a_jwt_shaped_domain_still_normalizes_but_is_no_longer_secret_shaped`); using it as a
refusal sample would make the "nothing was written" assertions pass for a reason that has
nothing to do with the screen. Only `secret_shapes.AGENT_TOKEN` and `secret_shapes.SLACK`
(both already lowercase, so lowering changes nothing about their shape) and
`secret_shapes.STRIPE` followed by a literal ``.example`` (Stripe's pattern is
case-insensitive, and the literal suffix gives the domain grammar's required dot, since
`STRIPE` alone carries none) stay shaped as a domain.

`invitations.create_invitation` is screened too, because `invitation.created` carries
``email_domain``. Its own address grammar, `transports.is_address`, is stricter than
`normalize_email`'s for a *domain* label specifically (no `/`, no `:`, and no `_`, which
`STRIPE` itself carries), so neither `SLACK` nor the Stripe-plus-``.example`` sample ever
reaches it as a domain; only `AGENT_TOKEN` does, because each of its four dot-separated
segments is alphanumeric-and-hyphen only, which is also a valid domain label. `is_address`'s
*local-part* grammar is more permissive, though (it allows `_`), so `STRIPE` as a local part
does reach `create_invitation` as a valid address: that is exactly
`ACCEPTED_SHAPED_LOCAL_PART`, reused below as this writer's own shaped-local-part control, and
the one case that would catch a mutation screening the whole address there instead of only its
domain (every `normalize_email` writer's own `ACCEPTED_SHAPED_LOCAL_PART` control already does,
since the Stripe pattern matches it regardless of position, which
`test_the_accepted_local_part_sample_passes_and_its_domain_is_not_shaped` asserts directly).
"""

import pytest
from console_api_fixtures import API, assert_no_secrets, console_client
from secret_shapes import AGENT_TOKEN, FREE_TEXT, FREE_TEXT_IDS, SLACK, STRIPE
from sqlalchemy import text
from test_console_api_people import PEOPLE
from test_execution import registry as registry
from test_execution import world as world
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime
from test_teammate_invitations import ADDRESS as INVITATION_ADDRESS
from test_teammate_invitations import admin_session as invitation_admin_session
from test_teammate_invitations import (
    bare_runtime,
    console_client_for,
    invitation_row,
)
from test_teammate_invitations import workspace as invitation_workspace
from test_text_screen_reasons import admin_session as admin_session
from text_screen_helpers import (
    assert_nothing_found,
    assert_refused_unquoted,
    kind_count,
    row_count,
)

from execbound import administration, passwords
from execbound.administration import AdministrationError
from execbound.invitations import InvitationError, create_invitation
from execbound.passwords import PasswordError, normalize_email
from execbound.secrets import secret_shaped
from execbound.surfaces import people_pages
from execbound.transports import is_address

EMAIL_KIND = "person.email_set"

# The only samples that both pass `normalize_email` and whose *domain* is still `secret_shaped`
# once it has lowercased the result: see the module docstring for why the rest of `FREE_TEXT`
# drops out, and for why `STRIPE` needs a literal `.example` suffix to carry a domain-shaped dot.
EMAIL_SAMPLES = (
    f"x@{AGENT_TOKEN}",
    f"x@{SLACK}",
    f"x@{STRIPE}.example",
)
EMAIL_SAMPLE_IDS = ("agent-token-domain", "slack-domain", "stripe-domain")

# The accepted control: a secret-shaped local part behind a plain domain. Screening the domain
# alone must let this through everywhere a shaped domain is refused.
ACCEPTED_SHAPED_LOCAL_PART = f"{STRIPE}@example.com"


def over_email_samples(argname):
    return pytest.mark.parametrize(argname, EMAIL_SAMPLES, ids=EMAIL_SAMPLE_IDS)


def _email_of(engine, tenant, principal):
    with engine.begin() as conn:
        return conn.execute(
            text(
                "SELECT email FROM execbound.principals WHERE tenant_id = :t AND principal_id = :p"
            ),
            {"t": tenant, "p": principal},
        ).scalar_one()


def _assert_shaped_domain(email):
    """`normalize_email` admits `email`, and its domain is `secret_shaped`: the fact every
    refusal sample below proves about itself first, since the field's own check and the
    screen share the same `INVALID_EMAIL` code, so a sample the field would have rejected on
    its own could never prove the screen fired. Returns the normalized value."""
    normalized = normalize_email(email)
    assert normalized is not None
    assert secret_shaped(normalized.rsplit("@", 1)[1]) is True
    return normalized


# -- What a sample must prove about itself before any writer sees it -----------------------


def test_most_free_text_samples_are_not_addresses_at_all():
    """BEARER and the embedded-Stripe sentence carry a space, DATABASE_URL carries a second
    ``@``: `normalize_email`'s grammar (`passwords._EMAIL`) forbids both outright, as a local
    part or as a domain. None of these three can ever be a domain-screen refusal sample,
    because `normalize_email` itself already refuses them before any screen runs. Indexed by
    name directly rather than filtered out of a loop over every `FREE_TEXT` entry, so renaming
    or removing one of these three ids makes this test raise instead of silently proving
    nothing about it."""
    for name in ("bearer", "database-url", "embedded"):
        value = FREE_TEXT[FREE_TEXT_IDS.index(name)]
        assert normalize_email(f"x@{value}") is None, name
        assert normalize_email(f"{value}@example.com") is None, name


def test_a_jwt_shaped_domain_still_normalizes_but_is_no_longer_secret_shaped():
    """The JWT alternative of `SECRET_TEXT` is deliberately case-sensitive (its own comment
    explains why: a lowercase hostname must not read as one), and `normalize_email` lowercases
    everything it accepts. A JWT-shaped domain therefore parses as an address and its domain
    must stay accepted: using it as a refusal sample would prove nothing about the screen."""
    jwt = FREE_TEXT[FREE_TEXT_IDS.index("jwt")]
    normalized = normalize_email(f"x@{jwt}")
    assert normalized is not None
    assert secret_shaped(normalized.rsplit("@", 1)[1]) is False


def test_each_email_sample_passes_normalize_email_and_its_domain_stays_secret_shaped():
    """Asserted once for all three here, and again at the top of every refusal test below
    through `_assert_shaped_domain`: the field's own check and the screen share the same
    `INVALID_EMAIL` code, so a sample the field would have rejected on its own could never
    prove the screen fired."""
    for sample in EMAIL_SAMPLES:
        _assert_shaped_domain(sample)


def test_the_accepted_local_part_sample_passes_and_its_domain_is_not_shaped():
    """The companion fact for the accepted control below: `STRIPE` as a local part behind
    `example.com` normalizes, and the *whole* address is itself `secret_shaped` (the Stripe
    pattern matches regardless of position), which is exactly why this sample would be wrongly
    refused by a screen over the whole address rather than the domain alone. Its domain alone
    is not `secret_shaped`, though, so every writer must still accept it when only the domain
    is screened."""
    normalized = normalize_email(ACCEPTED_SHAPED_LOCAL_PART)
    assert normalized is not None
    assert secret_shaped(normalized) is True
    assert secret_shaped(normalized.rsplit("@", 1)[1]) is False


def test_a_bare_slack_host_is_not_shaped_like_a_webhook():
    """A bare host with no ``/services/`` path is not a Slack webhook's shape at all.
    Exercised directly against `people_pages.set_email` by
    `test_a_bare_slack_host_as_a_set_email_address_is_still_accepted` below; every writer here
    shares this same `secret_shaped` check, so proving the shape is not a match once is proving
    it for all of them."""
    normalized = normalize_email("x@hooks.slack.com")
    assert normalized == "x@hooks.slack.com"
    assert secret_shaped(normalized.rsplit("@", 1)[1]) is False


# -- surfaces/people_pages.py `set_email` ---------------------------------------------------


@over_email_samples("email")
def test_a_set_email_address_shaped_like_a_secret_is_refused_unquoted(
    db, world, admin_engine, runtime, admin_session, email
):
    tenant = world["identity"].tenant_id
    target = world["human"].principal_id
    _assert_shaped_domain(email)
    before = kind_count(admin_engine, tenant, EMAIL_KIND)
    with pytest.raises(AdministrationError) as refused:
        people_pages.set_email(runtime, admin_session, target, email)
    assert_refused_unquoted(refused, "INVALID_EMAIL", email)
    assert_nothing_found(admin_engine, tenant)
    assert kind_count(admin_engine, tenant, EMAIL_KIND) == before
    assert _email_of(admin_engine, tenant, target) is None


def test_a_plain_set_email_address_is_still_accepted(
    db, world, admin_engine, runtime, admin_session
):
    tenant = world["identity"].tenant_id
    target = world["human"].principal_id
    before = kind_count(admin_engine, tenant, EMAIL_KIND)
    stored = people_pages.set_email(runtime, admin_session, target, "dana@example.com")
    assert stored == "dana@example.com"
    assert kind_count(admin_engine, tenant, EMAIL_KIND) == before + 1
    assert _email_of(admin_engine, tenant, target) == "dana@example.com"


def test_a_bare_slack_host_as_a_set_email_address_is_still_accepted(
    db, world, admin_engine, runtime, admin_session
):
    tenant = world["identity"].tenant_id
    target = world["human"].principal_id
    before = kind_count(admin_engine, tenant, EMAIL_KIND)
    stored = people_pages.set_email(runtime, admin_session, target, "x@hooks.slack.com")
    assert stored == "x@hooks.slack.com"
    assert kind_count(admin_engine, tenant, EMAIL_KIND) == before + 1
    assert _email_of(admin_engine, tenant, target) == "x@hooks.slack.com"


def test_a_secret_shaped_local_part_is_still_accepted_when_the_domain_is_not_set_email(
    db, world, admin_engine, runtime, admin_session
):
    tenant = world["identity"].tenant_id
    target = world["human"].principal_id
    normalized = normalize_email(ACCEPTED_SHAPED_LOCAL_PART)
    before = kind_count(admin_engine, tenant, EMAIL_KIND)
    stored = people_pages.set_email(runtime, admin_session, target, ACCEPTED_SHAPED_LOCAL_PART)
    assert stored == normalized
    assert kind_count(admin_engine, tenant, EMAIL_KIND) == before + 1
    assert _email_of(admin_engine, tenant, target) == normalized


def test_the_console_people_route_refuses_a_secret_shaped_email_as_a_bad_value(
    db, runtime, admin_engine, world
):
    """`REFUSALS` in `surfaces/console_api/directory.py` already maps `INVALID_EMAIL` to a
    400 naming `email`, for the field's own rejections; this proves the screen's refusal
    reaches the console the same way."""
    tenant = world["identity"].tenant_id
    human = str(world["human"].principal_id)
    before = kind_count(admin_engine, tenant, EMAIL_KIND)
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        refused = client.post(f"{PEOPLE}/{human}/email", {"email": f"x@{AGENT_TOKEN}"})
    assert refused.status_code == 400, refused.text
    body = refused.json()
    assert body["code"] == "INVALID_BODY" and body["fields"] == ["email"]
    assert_no_secrets(refused)
    assert kind_count(admin_engine, tenant, EMAIL_KIND) == before


# -- administration.py `invite_person` -------------------------------------------------------

CREATED_KIND = "principal.created"


@over_email_samples("email")
def test_an_invited_persons_address_shaped_like_a_secret_is_refused_unquoted(
    world, admin_engine, runtime, tmp_path, email
):
    tenant = world["identity"].tenant_id
    _assert_shaped_domain(email)
    before_email = kind_count(admin_engine, tenant, EMAIL_KIND)
    before_created = kind_count(admin_engine, tenant, CREATED_KIND)
    before_rows = row_count(admin_engine, tenant, "principals")
    output = tmp_path / "code.txt"
    with pytest.raises(AdministrationError) as refused:
        administration.invite_person(
            admin_engine,
            tenant,
            email,
            "ADMIN",
            label="New administrator",
            actor=world["admin"].principal_id,
            origin="https://example.test",
            output=output,
            now=runtime.clock.now(),
        )
    assert_refused_unquoted(refused, "INVALID_EMAIL", email)
    assert_nothing_found(admin_engine, tenant)
    assert kind_count(admin_engine, tenant, EMAIL_KIND) == before_email
    assert kind_count(admin_engine, tenant, CREATED_KIND) == before_created
    assert row_count(admin_engine, tenant, "principals") == before_rows
    assert not output.exists()


def test_a_plain_invited_persons_address_is_still_accepted(world, admin_engine, runtime, tmp_path):
    tenant = world["identity"].tenant_id
    before_email = kind_count(admin_engine, tenant, EMAIL_KIND)
    before_created = kind_count(admin_engine, tenant, CREATED_KIND)
    before_rows = row_count(admin_engine, tenant, "principals")
    output = tmp_path / "code.txt"
    invited = administration.invite_person(
        admin_engine,
        tenant,
        "new-admin-5@example.com",
        "ADMIN",
        label="New administrator",
        actor=world["admin"].principal_id,
        origin="https://example.test",
        output=output,
        now=runtime.clock.now(),
    )
    assert invited.email == "new-admin-5@example.com"
    assert invited.created is True
    assert kind_count(admin_engine, tenant, EMAIL_KIND) == before_email + 1
    assert kind_count(admin_engine, tenant, CREATED_KIND) == before_created + 1
    assert row_count(admin_engine, tenant, "principals") == before_rows + 1
    # The counterpart to the refusal test's `assert not output.exists()`: the same file the
    # refusal must never create, a plain invitation does.
    assert output.exists()


def test_a_secret_shaped_local_part_is_still_accepted_when_the_domain_is_not_invite_person(
    world, admin_engine, runtime, tmp_path
):
    tenant = world["identity"].tenant_id
    normalized = normalize_email(ACCEPTED_SHAPED_LOCAL_PART)
    before_email = kind_count(admin_engine, tenant, EMAIL_KIND)
    invited = administration.invite_person(
        admin_engine,
        tenant,
        ACCEPTED_SHAPED_LOCAL_PART,
        "ADMIN",
        label="New administrator",
        actor=world["admin"].principal_id,
        origin="https://example.test",
        output=tmp_path / "code.txt",
        now=runtime.clock.now(),
    )
    assert invited.email == normalized
    assert kind_count(admin_engine, tenant, EMAIL_KIND) == before_email + 1


# -- passwords.py `set_email` (no caller under `src/`; screened and tested directly anyway,
# -- since it is a public function that writes `person.email_set`) --------------------------


@over_email_samples("email")
def test_a_password_module_set_email_address_shaped_like_a_secret_is_refused_unquoted(
    db, world, admin_engine, email
):
    tenant = world["identity"].tenant_id
    target = world["human"].principal_id
    _assert_shaped_domain(email)
    before = kind_count(admin_engine, tenant, EMAIL_KIND)
    with pytest.raises(PasswordError) as refused:
        passwords.set_email(db, tenant, world["admin"].principal_id, target, email)
    assert_refused_unquoted(refused, "INVALID_EMAIL", email)
    assert_nothing_found(admin_engine, tenant)
    assert kind_count(admin_engine, tenant, EMAIL_KIND) == before
    assert _email_of(admin_engine, tenant, target) is None


def test_a_plain_password_module_set_email_address_is_still_accepted(db, world, admin_engine):
    tenant = world["identity"].tenant_id
    target = world["human"].principal_id
    before = kind_count(admin_engine, tenant, EMAIL_KIND)
    stored = passwords.set_email(
        db, tenant, world["admin"].principal_id, target, "dana6@example.com"
    )
    assert stored == "dana6@example.com"
    assert kind_count(admin_engine, tenant, EMAIL_KIND) == before + 1
    assert _email_of(admin_engine, tenant, target) == "dana6@example.com"


def test_a_secret_shaped_local_part_is_still_accepted_when_the_domain_is_not_password_module(
    db, world, admin_engine
):
    tenant = world["identity"].tenant_id
    target = world["human"].principal_id
    normalized = normalize_email(ACCEPTED_SHAPED_LOCAL_PART)
    before = kind_count(admin_engine, tenant, EMAIL_KIND)
    stored = passwords.set_email(
        db, tenant, world["admin"].principal_id, target, ACCEPTED_SHAPED_LOCAL_PART
    )
    assert stored == normalized
    assert kind_count(admin_engine, tenant, EMAIL_KIND) == before + 1
    assert _email_of(admin_engine, tenant, target) == normalized


# -- invitations.py `create_invitation` (`invitation.created` also carries a domain,
# -- `email_domain`) -------------------------------------------------------------------------

INVITATION_CREATED_KIND = "invitation.created"
# `is_address` (`transports.py`) accepts a looser local part than domain: its local-part class
# allows `_`, its domain-label class does not. `STRIPE` contains `_`, which no domain label
# admits, so the Stripe-plus-`.example` sample never reaches `create_invitation` as a domain;
# `SLACK` never does either, since it carries `/` and `:`, which neither half of
# `is_address` admits. `STRIPE` as a *local* part does reach it, though: that is
# `ACCEPTED_SHAPED_LOCAL_PART`,
# reused below as this writer's own shaped-local-part control. Only `AGENT_TOKEN` reaches it
# as a domain, because each of its four dot-separated segments is alphanumeric-and-hyphen
# only, which is also a valid domain label.


def test_is_address_only_accepts_the_agent_token_sample_among_email_samples():
    assert is_address(f"x@{AGENT_TOKEN}") is True
    assert is_address(f"x@{SLACK}") is False
    assert is_address(f"x@{STRIPE}.example") is False
    assert is_address(ACCEPTED_SHAPED_LOCAL_PART.lower()) is True


@pytest.fixture
def invitation_world(db, admin_engine):
    """One workspace ready for `create_invitation`, with its own runtime and an
    administrator's signed-in `Session`, built once so the tests below don't each repeat the
    same three lines of setup."""
    where = invitation_workspace(admin_engine)
    runtime = bare_runtime(db)
    session = invitation_admin_session(db, admin_engine, where)
    return {
        "tenant": where["tenant_id"],
        "admin": where["admin"],
        "runtime": runtime,
        "session": session,
    }


def _invite(invitation_world, email):
    return create_invitation(invitation_world["runtime"], invitation_world["session"], email, None)


def test_an_invitation_address_shaped_like_a_secret_is_refused_unquoted(
    db, admin_engine, invitation_world
):
    tenant = invitation_world["tenant"]
    email = f"x@{AGENT_TOKEN}"
    assert is_address(email) is True
    before_kind = kind_count(admin_engine, tenant, INVITATION_CREATED_KIND)
    before_rows = row_count(admin_engine, tenant, "workspace_invitations")
    with pytest.raises(InvitationError) as refused:
        _invite(invitation_world, email)
    assert_refused_unquoted(refused, "INVALID_EMAIL", email)
    assert_nothing_found(admin_engine, tenant)
    assert kind_count(admin_engine, tenant, INVITATION_CREATED_KIND) == before_kind
    assert row_count(admin_engine, tenant, "workspace_invitations") == before_rows


def test_a_plain_invitation_address_is_still_accepted(db, admin_engine, invitation_world):
    tenant = invitation_world["tenant"]
    before_kind = kind_count(admin_engine, tenant, INVITATION_CREATED_KIND)
    before_rows = row_count(admin_engine, tenant, "workspace_invitations")
    created = _invite(invitation_world, INVITATION_ADDRESS)
    assert created["email"] == INVITATION_ADDRESS
    assert kind_count(admin_engine, tenant, INVITATION_CREATED_KIND) == before_kind + 1
    assert row_count(admin_engine, tenant, "workspace_invitations") == before_rows + 1
    row = invitation_row(admin_engine, tenant, created["invitation_id"])
    assert row["email"] == INVITATION_ADDRESS


def test_a_shaped_local_part_invitation_is_still_accepted_when_the_domain_is_not(
    db, admin_engine, invitation_world
):
    """The companion control for `create_invitation`'s domain screen, and the one sample here
    that would catch a mutation screening the whole address there instead of only its domain:
    as with the three `normalize_email` writers above, `STRIPE` reaches this writer as a local
    part (`is_address` admits `_` there, which its domain grammar refuses), and the whole
    lowercased address is itself `secret_shaped`, not only its domain."""
    tenant = invitation_world["tenant"]
    lowered = ACCEPTED_SHAPED_LOCAL_PART.lower()
    assert is_address(lowered) is True
    assert secret_shaped(lowered) is True
    before_kind = kind_count(admin_engine, tenant, INVITATION_CREATED_KIND)
    before_rows = row_count(admin_engine, tenant, "workspace_invitations")
    created = _invite(invitation_world, ACCEPTED_SHAPED_LOCAL_PART)
    assert created["email"] == lowered
    assert kind_count(admin_engine, tenant, INVITATION_CREATED_KIND) == before_kind + 1
    assert row_count(admin_engine, tenant, "workspace_invitations") == before_rows + 1
    row = invitation_row(admin_engine, tenant, created["invitation_id"])
    assert row["email"] == lowered


def test_the_console_teammate_invitation_route_refuses_a_secret_shaped_email(
    db, admin_engine, invitation_world
):
    """The route's own `REFUSALS` (`surfaces/console_api/teammate_invitations.py`) already
    maps `INVALID_EMAIL` to a 400 naming `email`, for the service's own rejections; this
    proves the domain screen's refusal reaches the console the same way."""
    tenant = invitation_world["tenant"]
    before_kind = kind_count(admin_engine, tenant, INVITATION_CREATED_KIND)
    with console_client_for(
        db, invitation_world["runtime"], admin_engine, tenant, invitation_world["admin"]
    ) as client:
        refused = client.post(API + "/teammate-invitations", {"email": f"x@{AGENT_TOKEN}"})
    assert refused.status_code == 400, refused.text
    body = refused.json()
    assert body["code"] == "INVALID_BODY" and body["fields"] == ["email"]
    assert_no_secrets(refused)
    assert kind_count(admin_engine, tenant, INVITATION_CREATED_KIND) == before_kind
