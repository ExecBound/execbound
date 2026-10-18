# SPDX-License-Identifier: AGPL-3.0-only
"""Account security offers a first password to an account that signs in only with a provider.

The store's own rules are in `test_first_password.py`; this is the page: the form appears only
for an account with no password, both entries are compared as bytes, every refusal is a
sentence on the page, and no response carries the password.
"""

import pytest
from sqlalchemy import text
from test_sign_in_surface import (
    ADDRESS,
    ORIGIN,
    StandIn,
    account,
    form_values,
    landed_at,
    sign_in,
    started,
)
from test_sign_in_surface import bound_provider as bound_provider
from test_sign_in_surface import client as client
from test_sign_in_surface import config as config
from test_sign_in_surface import connector as connector
from test_sign_in_surface import live_provider as live_provider
from test_sign_in_surface import providers as providers
from test_sign_in_surface import registry as registry
from test_sign_in_surface import runtime as runtime
from test_sign_in_surface import signed_up as signed_up
from test_sign_in_surface import world as world

pytestmark = pytest.mark.integration

FORM = "/account/security/password"
CHOSEN = "Grüße aus Köln, 2026"


def provider_only(admin_engine) -> None:
    """Remove the password the fixture's sign-in carried into the account it made, leaving
    the account as a provider signup leaves it."""
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "DELETE FROM execbound.user_passwords WHERE account_id="
                "(SELECT account_id FROM execbound.user_accounts WHERE email=:e)"
            ),
            {"e": ADDRESS},
        )


def through_google(client) -> None:
    answer = started(client)
    state = answer.headers["location"].split("state=", 1)[1]
    assert landed_at(client.get(f"/login/google/callback?code=c&state={state}")) == "/approvals"


def add(client, password: str, confirm: str):
    values = form_values(client.get("/account/security").text, FORM)
    return client.post(
        FORM,
        data={**values, "password": password, "confirm": confirm},
        headers={"Origin": ORIGIN},
    )


@pytest.mark.parametrize("providers", [[StandIn(account=account())]], indirect=True)
def test_a_provider_account_adds_a_password_and_then_signs_in_with_it(
    client, providers, bound_provider, admin_engine
):
    through_google(client)
    provider_only(admin_engine)
    assert "Add a password" in client.get("/account/security").text
    different = add(client, CHOSEN, CHOSEN + "!")
    assert different.status_code == 200
    assert "The two passwords are not the same." in different.text
    added = add(client, CHOSEN, CHOSEN)
    assert added.status_code == 200
    assert "Your password is set." in added.text
    for answer in (different, added):
        assert CHOSEN not in answer.text
    # Set once, the form is gone: a password is changed from settings, never here.
    assert "Add a password" not in client.get("/account/security").text
    client.cookies.clear()
    assert sign_in(client, ADDRESS, CHOSEN).status_code == 303


@pytest.mark.parametrize("providers", [[StandIn(account=account())]], indirect=True)
def test_a_sign_in_older_than_five_minutes_is_told_to_sign_in_again(
    client, providers, bound_provider, admin_engine
):
    through_google(client)
    provider_only(admin_engine)
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.account_sessions SET created_at=now()-interval '6 minutes' "
                "WHERE account_id=(SELECT account_id FROM execbound.user_accounts WHERE email=:e)"
            ),
            {"e": ADDRESS},
        )
    refused = add(client, CHOSEN, CHOSEN)
    assert refused.status_code == 200
    assert "Sign in again first" in refused.text
    assert "Add a password" in refused.text


@pytest.mark.parametrize("providers", [[StandIn(account=account())]], indirect=True)
def test_an_account_with_a_password_is_offered_no_form_and_the_route_refuses(
    client, providers, bound_provider
):
    through_google(client)
    assert "Add a password" not in client.get("/account/security").text
    values = form_values(client.get("/account/security").text, "/account/link/google")
    refused = client.post(
        FORM,
        data={"csrf": values["csrf"], "password": CHOSEN, "confirm": CHOSEN},
        headers={"Origin": ORIGIN},
    )
    assert refused.status_code == 200
    assert "already has a password" in refused.text


@pytest.mark.parametrize("providers", [[StandIn(account=account())]], indirect=True)
def test_the_form_needs_its_csrf_and_its_own_fields(
    client, providers, bound_provider, admin_engine
):
    through_google(client)
    provider_only(admin_engine)
    values = form_values(client.get("/account/security").text, FORM)
    for data in (
        {**values, "csrf": "x" * 43, "password": CHOSEN, "confirm": CHOSEN},
        {**values, "password": CHOSEN},
        {**values, "password": CHOSEN, "confirm": CHOSEN, "extra": "1"},
    ):
        assert client.post(FORM, data=data, headers={"Origin": ORIGIN}).status_code == 403
    assert "Add a password" in client.get("/account/security").text
