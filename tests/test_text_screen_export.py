# SPDX-License-Identifier: AGPL-3.0-only
"""End to end: text shaped like a secret, typed by a person or vouched for by an identity
provider, never stops a tenant's history leaving through either export.

One write of each kind the screens refuse is attempted with a shaped value: a reason, a name,
a registry entry, an email address and a policy bundle. Then a person signs in through the
tenant's own directory, and another through Google, each with a subject of that shape, which
is withheld rather than refused. Afterwards the event export reads the whole chain in one pass
and stays `ACTIVE`, no audit payload holds a finding, and the replay export, which also reads
every bundle an event references, publishes and verifies.

No write here sits in `pytest.raises`. A screen taken away lets its write land, and then it is
the exports that fail, which is the claim this file makes; which writes were refused, and with
which code, is checked last. Each per-boundary test file proves its own screen; this one proves
that together they keep both exports open.
"""

from uuid import uuid4

import pytest
from secret_shapes import AGENT_TOKEN, JWT, STRIPE
from sqlalchemy import text
from test_directory_store import account, enabled
from test_directory_store import cast as cast
from test_directory_store import clock as clock
from test_directory_store import settings as settings
from test_execution import registry as registry
from test_execution import world as world
from test_monitoring_worker import receiver as receiver
from test_request_secret_screen import exports
from test_workspace_accounts import adopt, enroll
from text_screen_helpers import assert_nothing_found, kind_count

from execbound import administration
from execbound import directory_store as directory
from execbound.administration import AdministrationError
from execbound.execution import activate_stop
from execbound.execution.models import ExecutionError
from execbound.passwords import bind_identity, normalize_email
from execbound.policy.models import Condition, Rule, Ruleset
from execbound.policy.rulesets import ruleset_bundle
from execbound.policy.store import PolicyStoreError, create_bundle
from execbound.replay.export import export_history, publish_export
from execbound.replay.verify import parse_export, verify_export
from execbound.requests import ResourceSelector
from execbound.resolution.models import SystemClock
from execbound.secrets import secret_shaped
from execbound.signin import ExternalAccount
from execbound.spaces import SpaceError, create_space
from execbound.user_accounts import provider_sign_in

pytestmark = pytest.mark.integration

# A shaped domain `normalize_email` admits and leaves shaped once it has lowercased it.
SHAPED_EMAIL = f"x@{AGENT_TOKEN}"
REFUSED = {
    "stop reason": "INVALID_REASON",
    "space name": "INVALID_NAME",
    "resource provider id": "INVALID_PROVIDER_ID",
    "invited address": "INVALID_EMAIL",
    "bundle note": "INVALID_TEXT",
}
WITHHELD_SIGN_INS = ("human_sign_in.directory", "human_sign_in.google")


def attempt(refusals, name, error, write):
    """Run one write a screen must refuse and record the code it was refused with, or `None`
    where it was written instead."""
    try:
        write()
    except error as raised:
        refusals[name] = raised.code
    else:
        refusals[name] = None


def latest(admin_engine, tenant, kind):
    with admin_engine.begin() as conn:
        return conn.execute(
            text(
                "SELECT payload FROM execbound.audit_events "
                "WHERE tenant_id = :t AND kind = :k ORDER BY sequence DESC LIMIT 1"
            ),
            {"t": tenant, "k": kind},
        ).scalar_one()


def test_shaped_text_from_people_and_the_identity_provider_leaves_both_exports_open(
    db, world, admin_engine, receiver, settings, cast, clock, tmp_path
):
    tenant = world["identity"].tenant_id
    # The directory's cast and the Google account live in the world's own tenant, so one
    # export reads every event this test makes.
    assert cast["tenant"] == tenant
    admin = world["admin"]
    # Each sample passes its field's own check, so a refusal below can only be the screen's.
    assert 1 <= len(STRIPE) <= 500
    assert ResourceSelector(kind="provider_id", value=STRIPE)
    normalized = normalize_email(SHAPED_EMAIL)
    assert normalized is not None and secret_shaped(normalized.rsplit("@", 1)[1])
    refusals: dict[str, str | None] = {}

    attempt(
        refusals,
        "stop reason",
        ExecutionError,
        lambda: activate_stop(db, admin, STRIPE, world["clock"]),
    )

    def space():
        with db.transaction(tenant) as conn:
            create_space(conn, tenant, admin.principal_id, STRIPE, None, credential=None)

    attempt(refusals, "space name", SpaceError, space)
    attempt(
        refusals,
        "resource provider id",
        AdministrationError,
        lambda: administration.create_resource(
            admin_engine,
            tenant,
            world["account"],
            "endpoint",
            STRIPE,
            world["inventory"],
            admin.principal_id,
        ),
    )
    attempt(
        refusals,
        "invited address",
        AdministrationError,
        lambda: administration.invite_person(
            admin_engine,
            tenant,
            SHAPED_EMAIL,
            "HUMAN_APPROVER",
            actor=admin.principal_id,
            origin="https://example.test",
            output=tmp_path / "code.txt",
            now=world["clock"].now(),
        ),
    )
    noted = Ruleset(
        rules=(
            Rule(
                id="allow-workstation",
                action="endpoint.isolate",
                effect="ALLOW",
                when=(Condition(kind="fact", name="role", operator="is", values=("workstation",)),),
                note=STRIPE,
            ),
        )
    )
    bundle = ruleset_bundle(
        noted, tenant_id=tenant, bundle_id=uuid4(), mappings=world["bundle"].mappings
    )
    attempt(
        refusals,
        "bundle note",
        PolicyStoreError,
        lambda: create_bundle(db, admin, bundle, world["clock"]),
    )

    # A directory sign-in that redeems an invitation, which links the subject and signs in.
    provider = enabled(db, settings, cast, clock)
    minted = directory.invite(db, tenant, cast["admin"], cast["approver"], provider)
    invitation, _ = directory.check_invitation(db, minted.code)
    row = directory.locate_provider(db, provider)
    directory.sign_in(db, settings, row, account(JWT), invitation_id=invitation, clock=clock)
    # A Google subject bound to a person, then signed in with.
    principal, _ = enroll(admin_engine, tenant)
    bind_identity(
        db,
        tenant,
        principal,
        provider="google",
        subject=STRIPE,
        email="member@example.test",
        display_name=None,
    )
    adopt(db, tenant, principal)
    google = ExternalAccount("google", STRIPE, "member@example.test", None)
    assert provider_sign_in(db, google, clock=SystemClock()).principal_id == principal

    # The claim: the event export reads the whole chain, every event, and stays active.
    assert exports(db, world, admin_engine, receiver) == ("ACTIVE", None)
    assert_nothing_found(admin_engine, tenant)
    # The replay export reads the chain again with every bundle an event references.
    history = export_history(db, admin, world["clock"])
    output, checkpoint = tmp_path / "history.json", tmp_path / "checkpoint.json"
    publish_export(db, admin, history, output=output, checkpoint=checkpoint, clock=world["clock"])
    verify_export(parse_export(output.read_bytes()), history.head)

    # Every write was refused by its screen, and each sign-in ran with its subject withheld.
    assert refusals == REFUSED
    assert not (tmp_path / "code.txt").exists()
    for kind in WITHHELD_SIGN_INS:
        assert kind_count(admin_engine, tenant, kind) == 1
        assert latest(admin_engine, tenant, kind)["subject"] == "WITHHELD"
