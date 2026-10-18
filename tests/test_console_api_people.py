# SPDX-License-Identifier: AGPL-3.0-only
"""The People area of the console API (#333).

Every route through the harness, then the People page's behaviour as JSON: the list with its
two filters, a labelled `New approver`, the detail's sections for an approver and for an
administrator, a credential issued once under `no-store` and revoked, scopes assigned and
unassigned, `End all sessions` felt by the person and sparing the administrator, and
deactivation atomic across credentials and sessions and refused for an ADMIN target, the actor
and a cross-tenant id, exactly as the page refuses them.
"""

from uuid import uuid4

import pytest
from console_api_fixtures import (
    API,
    ORIGIN,
    assert_no_secrets,
    console_client,
    console_config,
    refusals,
)
from space_fixtures import default_space, make_space, seat
from sqlalchemy import text
from test_console_api_agents import without_token
from test_console_api_approvals import _number, decide, detail
from test_emergency_stop import audit
from test_execution import provision_identity
from test_execution import registry as registry
from test_execution import world as world
from test_human_surface import pending
from test_key_last_used import legacy_factor, member_factor
from test_key_last_used import person as key_person
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

from execbound.identity import AuthenticationFailed, authenticate
from execbound.surfaces.sessions import SessionError, issue_session, load_session

PEOPLE = API + "/people"
ZERO = "00000000-0000-0000-0000-000000000000"
ROUTES = [
    (PEOPLE, "GET", None),
    (PEOPLE, "POST", {"label": "x"}),
    (f"{PEOPLE}/{ZERO}", "GET", None),
    (f"{PEOPLE}/{ZERO}/label", "POST", {"label": "x"}),
    (f"{PEOPLE}/{ZERO}/email", "POST", {"email": "x@example.com"}),
    (f"{PEOPLE}/{ZERO}/password-link", "POST", {"lifetime": "24"}),
    (f"{PEOPLE}/{ZERO}/directory-invite", "POST", {"provider_id": ZERO, "lifetime": "168"}),
    (f"{PEOPLE}/{ZERO}/directory-invite/revoke", "POST", {"invitation_id": ZERO}),
    (f"{PEOPLE}/{ZERO}/directory-link", "POST", {"provider_id": ZERO, "subject": "x"}),
    (f"{PEOPLE}/{ZERO}/directory-unlink", "POST", {}),
    (f"{PEOPLE}/{ZERO}/credentials/issue", "POST", {"lifetime": "8"}),
    (f"{PEOPLE}/{ZERO}/credentials/{ZERO}/revoke", "POST", {}),
    (f"{PEOPLE}/{ZERO}/scopes/assign", "POST", {"target": ZERO, "action": "endpoint.isolate"}),
    (f"{PEOPLE}/{ZERO}/scopes/unassign", "POST", {"target": ZERO, "action": "endpoint.isolate"}),
    (f"{PEOPLE}/{ZERO}/sessions/end", "POST", {}),
    (f"{PEOPLE}/{ZERO}/deactivate", "POST", {"reason": "x"}),
    (f"{PEOPLE}/{ZERO}/reactivate", "POST", {}),
]


@pytest.mark.parametrize("path,method", [(path, method) for path, method, _ in ROUTES])
def test_every_route_refuses_a_bearer_and_no_session(
    db, runtime, seeded, admin_engine, world, path, method
):
    results = refusals(db, runtime, seeded, admin_engine, world, path, method)
    assert results["bearer"].status_code == 403 and results["bearer"].json()["code"] == "FORBIDDEN"
    assert results["audited"] == 1
    assert results["no_session"].status_code == 401


def test_an_approver_is_refused_on_every_route(db, runtime, admin_engine, world):
    with console_client(db, runtime, admin_engine, world["human"]) as approver:
        for path, method, body in ROUTES:
            response = approver.get(path) if method == "GET" else approver.post(path, body)
            assert response.status_code == 403, (path, response.text)
            assert response.json()["code"] == "FORBIDDEN"
            assert_no_secrets(response)


def test_the_list_shows_people_with_counts_and_filters(db, runtime, admin_engine, world, seeded):
    human, admin = str(world["human"].principal_id), str(world["admin"].principal_id)
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        page = client.get(PEOPLE)
        assert page.status_code == 200, page.text
        assert_no_secrets(page)
        rows = {row["principal_id"]: row for row in page.json()["people"]}
        assert set(rows) == {human, admin}
        assert rows[human]["kind"] == "HUMAN_APPROVER" and rows[human]["scopes"] == 1
        assert rows[human]["live"] == 1 and rows[human]["label"] is None
        assert rows[admin]["kind"] == "ADMIN" and rows[admin]["sessions"] == 1
        assert rows[admin]["last_sign_in"] is not None and rows[admin]["active"]
        assert str(world["identity"].principal_id) not in rows, "agents are not people"
        assert str(seeded["principals"][1]) not in rows
        admins = client.get(PEOPLE, params={"kind": "ADMIN"}).json()["people"]
        assert [row["principal_id"] for row in admins] == [admin]
        assert client.get(PEOPLE, params={"state": "deactivated"}).json()["people"] == []
        for bad in ({"state": "nope"}, {"kind": "AGENT"}, {"foo": "1"}):
            refused = client.get(PEOPLE, params=bad)
            assert refused.status_code == 400 and refused.json()["code"] == "INVALID_REQUEST", bad


def test_a_new_approver_needs_a_label_and_the_detail_has_every_section(
    db, runtime, admin_engine, world, seeded
):
    tenant = world["identity"].tenant_id
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        assert client.post(PEOPLE, {"label": "  "}).json()["fields"] == ["label"]
        made = client.post(PEOPLE, {"label": "  Dana Reyes  "})
        assert made.status_code == 200, made.text
        principal = made.json()["principal_id"]
        assert audit(admin_engine, tenant, "principal.labelled")[-1]["label"] == "Dana Reyes"
        detail = client.get(f"{PEOPLE}/{principal}")
        assert detail.status_code == 200 and detail.json()["person"]["label"] == "Dana Reyes"
        assert_no_secrets(detail)
        # The fixture's approver: every section, the scope with its target label, no session.
        approver = client.get(f"{PEOPLE}/{world['human'].principal_id}").json()
        assert approver["person"]["kind"] == "HUMAN_APPROVER" and not approver["is_self"]
        [scope] = approver["scopes"]
        assert scope["action"] == "endpoint.isolate"
        assert scope["canonical_target_id"] == str(world["canonical"])
        assert scope["labels"] and "device" in scope["labels"], "the provider identifier labels it"
        assert approver["targets"][0]["canonical_target_id"] == str(world["canonical"])
        assert "endpoint.isolate" in approver["actions"]
        assert len(approver["credentials"]) == 1 and approver["credentials"][0]["state"] == "live"
        assert approver["sessions"] == [] and approver["history"]["decisions"] == []
        assert approver["history"]["events"] == [] and approver["history_limit"] == 20
        # The administrator's own page: a session with its device, sign-ins, and their events.
        me = client.get(f"{PEOPLE}/{world['admin'].principal_id}").json()
        assert me["person"]["kind"] == "ADMIN" and me["is_self"]
        assert len(me["sessions"]) == 1 and me["scopes"] == []
        assert me["targets"] == [
            {"canonical_target_id": str(world["canonical"]), "labels": "device-01"}
        ]
        assert me["history"]["sign_ins"][0]["state"] == "active"
        assert me["history"]["decisions"] == []
        assert [event["words"] for event in me["history"]["events"]][:2] == [
            "Labelled",
            "Created",
        ]
        assert me["history"]["events"][0]["label"] == "Dana Reyes"
        relabelled = client.post(f"{PEOPLE}/{principal}/label", {"label": "Dana"})
        assert relabelled.status_code == 200 and relabelled.json()["person"]["label"] == "Dana"
        # Unknown, cross-tenant and agent ids answer 404 alike.
        for missing in (uuid4(), seeded["principals"][1], world["identity"].principal_id):
            assert client.get(f"{PEOPLE}/{missing}").status_code == 404, missing
            assert client.post(f"{PEOPLE}/{missing}/label", {"label": "x"}).status_code == 404


def test_a_credential_is_issued_once_and_revoked_and_never_for_an_administrator(
    db, runtime, admin_engine, world
):
    human, admin = str(world["human"].principal_id), str(world["admin"].principal_id)
    tenant = world["identity"].tenant_id
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        issued = client.post(f"{PEOPLE}/{human}/credentials/issue", {"lifetime": "1"})
        assert issued.status_code == 200 and issued.headers["cache-control"] == "no-store"
        body = without_token(issued)
        token = issued.json()["token"]
        assert body["kind"] == "HUMAN_APPROVER" and body["principal_id"] == human
        assert authenticate(runtime.db, token).principal_id == world["human"].principal_id
        credential = body["credential_id"]
        detail = client.get(f"{PEOPLE}/{human}")
        assert token not in detail.text
        assert {row["credential_id"] for row in detail.json()["credentials"]} >= {credential}
        revoked = client.post(f"{PEOPLE}/{human}/credentials/{credential}/revoke", {})
        assert revoked.status_code == 200
        assert {
            row["state"]
            for row in revoked.json()["credentials"]
            if row["credential_id"] == credential
        } == {"revoked"}
        with pytest.raises(AuthenticationFailed):
            authenticate(runtime.db, token)
        assert audit(admin_engine, tenant, "credential.revoked")[-1]["credential_id"] == credential
        assert (
            client.post(f"{PEOPLE}/{human}/credentials/{credential}/revoke", {}).status_code == 409
        )
        # An administrator is given no console credential, and theirs is not revoked here.
        refused = client.post(f"{PEOPLE}/{admin}/credentials/issue", {"lifetime": "1"})
        assert refused.status_code == 400 and refused.json()["code"] == "INVALID_PRINCIPAL"
        assert "token" not in refused.json()
        with admin_engine.connect() as conn:
            own = str(
                conn.execute(
                    text(
                        "SELECT credential_id FROM execbound.credentials "
                        "WHERE tenant_id = :t AND principal_id = :p"
                    ),
                    {"t": tenant, "p": world["admin"].principal_id},
                ).scalar_one()
            )
        assert client.post(f"{PEOPLE}/{admin}/credentials/{own}/revoke", {}).status_code == 409
        # A credential of another principal cannot be revoked under this person's path.
        assert client.post(f"{PEOPLE}/{human}/credentials/{own}/revoke", {}).status_code == 404


def test_scopes_are_assigned_and_unassigned_through_the_approvers_functions(
    db, runtime, admin_engine, world
):
    human = str(world["human"].principal_id)
    tenant = world["identity"].tenant_id
    canonical = str(world["canonical"])
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        path = f"{PEOPLE}/{human}/scopes/assign"
        assert client.post(path, {"target": "nope", "action": "endpoint.isolate"}).json()[
            "fields"
        ] == ["target"]
        bad = client.post(path, {"target": canonical, "action": "endpoint.explode"})
        assert bad.status_code == 400 and bad.json()["fields"] == ["action"]
        elsewhere = client.post(path, {"target": str(uuid4()), "action": "endpoint.isolate"})
        assert elsewhere.status_code == 400 and elsewhere.json()["fields"] == ["target"]
        assigned = client.post(path, {"target": canonical, "action": "endpoint.lift_isolation"})
        assert assigned.status_code == 200, assigned.text
        assert sorted(row["action"] for row in assigned.json()["scopes"]) == [
            "endpoint.isolate",
            "endpoint.lift_isolation",
        ]
        assert audit(admin_engine, tenant, "approval_scope.assigned")[-1]["approver_id"] == human
        unassigned = client.post(
            f"{PEOPLE}/{human}/scopes/unassign",
            {"target": canonical, "action": "endpoint.lift_isolation"},
        )
        assert unassigned.status_code == 200
        assert [row["action"] for row in unassigned.json()["scopes"]] == ["endpoint.isolate"]
        again = client.post(
            f"{PEOPLE}/{human}/scopes/unassign",
            {"target": canonical, "action": "endpoint.lift_isolation"},
        )
        assert again.status_code == 409 and again.json()["code"] == "CONFLICT"
        # An existing administrator can be assigned review permission as the same person.
        admin = str(world["admin"].principal_id)
        assigned = client.post(
            f"{PEOPLE}/{admin}/scopes/assign", {"target": canonical, "action": "endpoint.isolate"}
        )
        assert assigned.status_code == 200, assigned.text
        assert assigned.json()["person"]["principal_id"] == admin
        assert len(assigned.json()["scopes"]) == 1


def test_end_all_sessions_ends_the_person_and_spares_the_administrator(
    db, runtime, admin_engine, world
):
    human, admin = str(world["human"].principal_id), str(world["admin"].principal_id)
    tenant = world["identity"].tenant_id
    extra = issue_session(runtime.db, world["human"], clock=runtime.clock, label="Safari on iPhone")
    with console_client(db, runtime, admin_engine, world["human"]) as approver:
        assert approver.get(API + "/session").status_code == 200
        with console_client(db, runtime, admin_engine, world["admin"]) as client:
            detail = client.get(f"{PEOPLE}/{human}").json()
            assert {row["label"] for row in detail["sessions"]} >= {"Safari on iPhone"}
            ended = client.post(f"{PEOPLE}/{human}/sessions/end", {})
            assert ended.status_code == 200, ended.text
            assert ended.json()["sessions"] == []
            assert client.get(PEOPLE).status_code == 200, "the administrator's session survives"
            own = client.post(f"{PEOPLE}/{admin}/sessions/end", {})
            assert own.status_code == 400 and own.json()["code"] == "INVALID_PRINCIPAL"
            assert client.get(PEOPLE).status_code == 200
        assert approver.get(API + "/session").status_code == 401
    with pytest.raises(SessionError):
        load_session(runtime.db, extra.token, clock=runtime.clock)
    ended = [
        event
        for event in audit(admin_engine, tenant, "human_session.revoked")
        if event.get("reason") == "ADMIN"
    ]
    assert len(ended) == 2 and {event["principal_id"] for event in ended} == {human}


def test_deactivation_is_atomic_and_refused_for_an_administrator_the_actor_and_elsewhere(
    db, runtime, admin_engine, world, seeded
):
    human, admin = str(world["human"].principal_id), str(world["admin"].principal_id)
    tenant = world["identity"].tenant_id
    extra = issue_session(runtime.db, world["human"], clock=runtime.clock, label="Safari on iPhone")
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        token = client.post(f"{PEOPLE}/{human}/credentials/issue", {"lifetime": "1"}).json()[
            "token"
        ]
        assert client.post(f"{PEOPLE}/{human}/deactivate", {"reason": " "}).json()["fields"] == [
            "reason"
        ]
        for target in (admin, seeded["principals"][1]):
            refused = client.post(f"{PEOPLE}/{target}/deactivate", {"reason": "no"})
            assert refused.status_code in {400, 404}, target
            assert refused.json()["code"] in {"INVALID_PRINCIPAL", "NOT_FOUND"}
        gone = client.post(f"{PEOPLE}/{human}/deactivate", {"reason": "left the team"})
        assert gone.status_code == 200, gone.text
        assert_no_secrets(gone)
        body = gone.json()
        assert not body["person"]["active"] and body["person"]["deactivated_at"]
        assert all(row["state"] == "revoked" for row in body["credentials"])
        assert body["sessions"] == []
        assert [row["action"] for row in body["scopes"]] == ["endpoint.isolate"], "scopes are kept"
        with pytest.raises(AuthenticationFailed):
            authenticate(runtime.db, token)
        with pytest.raises(SessionError):
            load_session(runtime.db, extra.token, clock=runtime.clock)
        event = audit(admin_engine, tenant, "principal.deactivated")[-1]
        assert event["reason"] == "left the team"
        assert event["credentials_revoked"] >= 2 and event["sessions_revoked"] == 1
        assert client.post(f"{PEOPLE}/{human}/deactivate", {"reason": "twice"}).status_code == 409
        refused = client.post(f"{PEOPLE}/{human}/credentials/issue", {"lifetime": "1"})
        assert refused.status_code == 400 and "token" not in refused.json()
        assert human not in {row["principal_id"] for row in client.get(PEOPLE).json()["people"]}
        listed = client.get(PEOPLE, params={"state": "deactivated"}).json()["people"]
        assert [row["principal_id"] for row in listed] == [human]
        back = client.post(f"{PEOPLE}/{human}/reactivate", {})
        assert back.status_code == 200 and back.json()["person"]["active"]
        assert all(row["state"] == "revoked" for row in back.json()["credentials"])
        assert [row["action"] for row in back.json()["scopes"]] == ["endpoint.isolate"]
        assert client.post(f"{PEOPLE}/{human}/reactivate", {}).status_code == 409
        assert client.post(f"{PEOPLE}/{admin}/reactivate", {}).status_code in {400, 409}


# The sign-in section (regular sign-in): an address and a show-once code.


def test_an_administrator_gives_a_person_an_address_and_a_code_shown_once(
    db, runtime, admin_engine, world
):
    """The address is a fact on the person; the code comes back once, beside the page to
    open, and is stored only as its digest. Nothing here sets a password for anybody."""
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        person = world["human"].principal_id
        addressed = admin.post(f"{PEOPLE}/{person}/email", {"email": "Dana@Example.com"})
        assert addressed.status_code == 200, addressed.text
        assert addressed.json()["sign_in"]["email"] == "dana@example.com"
        assert addressed.json()["sign_in"]["has_password"] is False
        assert_no_secrets(addressed)

        minted = admin.post(f"{PEOPLE}/{person}/password-link", {"lifetime": "24"})
        assert minted.status_code == 200, minted.text
        body = minted.json()
        assert body["code"].startswith(f"ebp1.{world['identity'].tenant_id}.{body['reset_id']}.")
        assert body["address"].endswith("/set-password")
        # The code is not part of the address: a link carrying one is a code in a log.
        assert body["code"] not in body["address"]
        assert minted.headers["Cache-Control"] == "no-store"

        after = admin.get(f"{PEOPLE}/{person}")
        assert after.json()["sign_in"]["pending_until"] is not None
        # The listing carries the pending code's expiry and never the code or its digest.
        assert_no_secrets(after)
        assert body["code"] not in after.text


def test_the_console_refuses_an_administrator_an_address_or_a_code(
    db, runtime, admin_engine, world
):
    """The 0021 invariant with a password in the world: the console still cannot create or
    change an administrator, so an administrator's address and code are owner tooling's."""
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        target = world["admin"].principal_id
        refused = admin.post(f"{PEOPLE}/{target}/email", {"email": "root@example.com"})
        assert refused.status_code == 400
        assert refused.json()["code"] == "INVALID_PRINCIPAL"
        code = admin.post(f"{PEOPLE}/{target}/password-link", {"lifetime": "24"})
        assert code.status_code == 400
        assert code.json()["code"] == "INVALID_PRINCIPAL"


def test_an_address_another_person_holds_is_refused_as_a_conflict(db, runtime, admin_engine, world):
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        first = world["human"].principal_id
        assert (
            admin.post(f"{PEOPLE}/{first}/email", {"email": "dana@example.com"}).status_code == 200
        )
        second = admin.post(API + "/people", {"label": "Sam"}).json()["principal_id"]
        clash = admin.post(f"{PEOPLE}/{second}/email", {"email": "dana@example.com"})
        assert clash.status_code == 409
        assert clash.json()["code"] == "CONFLICT"


@pytest.mark.parametrize("email", ["", "dana", "dana@example", "a" * 260])
def test_a_string_that_is_not_an_address_is_refused_naming_the_field(
    db, runtime, admin_engine, world, email
):
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        person = world["human"].principal_id
        refused = admin.post(f"{PEOPLE}/{person}/email", {"email": email})
        assert refused.status_code == 400
        assert refused.json()["code"] == "INVALID_BODY"
        assert refused.json().get("fields") == ["email"]


@pytest.mark.parametrize("lifetime", ["720", "2160"])
def test_a_code_lifetime_beyond_fourteen_days_is_refused(
    db, runtime, admin_engine, world, lifetime
):
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        person = world["human"].principal_id
        admin.post(f"{PEOPLE}/{person}/email", {"email": "dana@example.com"})
        refused = admin.post(f"{PEOPLE}/{person}/password-link", {"lifetime": lifetime})
        assert refused.status_code == 400
        assert refused.json()["code"] == "INVALID_BODY"
        assert refused.json().get("fields") == ["lifetime"]


def test_a_code_needs_an_address_first(db, runtime, admin_engine, world):
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        person = admin.post(API + "/people", {"label": "Nameless"}).json()["principal_id"]
        refused = admin.post(f"{PEOPLE}/{person}/password-link", {"lifetime": "24"})
        assert refused.status_code == 400
        assert refused.json()["code"] == "INVALID_BODY"


# ---- the tenant's own directory on a person (#177, #241) ---------------------------------


@pytest.fixture
def directory_console(db, runtime, admin_engine, world):
    """An administrator's console against a tenant that has an enabled directory."""
    from idp_fixtures import (
        CLIENT_ID,
        CLIENT_SECRET,
        ISSUER,
        NAME,
        SUBJECT,
        USERNAME,
        StandIn,
        directory_key,
        discovery_document,
    )

    from execbound import directory_store
    from execbound.directory import DirectoryAccount, DirectoryConfig, Discovery
    from execbound.envelope import KEY_BYTES, KeyRing

    stand_in = StandIn(directory_key())
    settings = DirectoryConfig(
        KeyRing("dir-v1", {"dir-v1": b"\x44" * KEY_BYTES}), ORIGIN, stand_in.client()
    )
    document = discovery_document()
    identity = world["admin"]
    provider = directory_store.register(
        db,
        settings,
        identity.tenant_id,
        identity.principal_id,
        name="Contoso",
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        subject_claim="oid",
        discovery=Discovery(
            ISSUER,
            document["authorization_endpoint"],
            document["token_endpoint"],
            document["jwks_uri"],
            None,
        ),
        clock=runtime.clock,
    )
    directory_store.link_self(
        db,
        identity.tenant_id,
        identity.principal_id,
        provider,
        DirectoryAccount(SUBJECT, NAME, USERNAME, "refresh"),
        clock=runtime.clock,
    )
    directory_store.set_state(
        db, identity.tenant_id, identity.principal_id, provider, "enabled", clock=runtime.clock
    )
    with console_client(
        db, runtime, admin_engine, identity, config=console_config(directory=settings)
    ) as made:
        yield made, str(provider)


def test_an_invitation_comes_back_once_beside_the_page_to_open(directory_console, world):
    admin, provider = directory_console
    person = world["human"].principal_id
    minted = admin.post(
        f"{PEOPLE}/{person}/directory-invite", {"provider_id": provider, "lifetime": "168"}
    )
    assert minted.status_code == 200, minted.text
    body = minted.json()
    assert body["code"].startswith("ebv1.")
    assert body["address"].endswith("/invite")
    # The code is not part of the address: a link carrying one is a code in a log.
    assert body["code"] not in body["address"]
    assert minted.headers["Cache-Control"] == "no-store"
    after = admin.get(f"{PEOPLE}/{person}")
    assert after.json()["sign_in"]["invitation"]["provider_id"] == provider
    assert body["code"] not in after.text
    assert_no_secrets(after)


def test_a_link_and_an_unlink_are_shown_and_then_gone(directory_console, world):
    admin, provider = directory_console
    person = world["human"].principal_id
    linked = admin.post(
        f"{PEOPLE}/{person}/directory-link",
        {"provider_id": provider, "subject": "00u-the-subject"},
    )
    assert linked.status_code == 200, linked.text
    link = linked.json()["sign_in"]["link"]
    assert link["subject"] == "00u-the-subject"
    assert link["via"] == "admin"
    assert link["provider_name"] == "Contoso"
    gone = admin.post(f"{PEOPLE}/{person}/directory-unlink", {})
    assert gone.status_code == 200
    assert gone.json()["sign_in"]["link"] is None


def test_an_administrator_target_is_refused_a_link_and_an_invitation(directory_console, world):
    admin, provider = directory_console
    person = world["admin"].principal_id
    for path, body in (
        ("directory-invite", {"provider_id": provider, "lifetime": "168"}),
        ("directory-link", {"provider_id": provider, "subject": "00u-someone"}),
    ):
        refused = admin.post(f"{PEOPLE}/{person}/{path}", body)
        assert refused.status_code == 403, (path, refused.text)
        assert refused.json()["code"] == "FORBIDDEN"


def test_an_invitation_is_revoked_by_its_identifier(directory_console, world):
    admin, provider = directory_console
    person = world["human"].principal_id
    minted = admin.post(
        f"{PEOPLE}/{person}/directory-invite", {"provider_id": provider, "lifetime": "24"}
    ).json()
    revoked = admin.post(
        f"{PEOPLE}/{person}/directory-invite/revoke", {"invitation_id": minted["reset_id"]}
    )
    assert revoked.status_code == 200, revoked.text
    assert revoked.json()["sign_in"]["invitation"] is None


@pytest.mark.parametrize("lifetime", ["720", "2160"])
def test_an_invitation_beyond_fourteen_days_is_refused(directory_console, world, lifetime):
    admin, provider = directory_console
    person = world["human"].principal_id
    refused = admin.post(
        f"{PEOPLE}/{person}/directory-invite", {"provider_id": provider, "lifetime": lifetime}
    )
    assert refused.status_code == 400
    assert refused.json().get("fields") == ["lifetime"]


# Second-factor status and the history's identifiers (#678): AK9 and AK12.


def test_ak9_people_carry_their_second_factor_as_enforcement_reads_it(
    db, runtime, admin_engine, world
):
    tenant = world["identity"].tenant_id
    a, b, c, d = (key_person(admin_engine, tenant) for _ in range(4))
    legacy_factor(admin_engine, tenant, a, enabled=True)
    member_factor(admin_engine, tenant, b, enabled=True)
    member_factor(admin_engine, tenant, d, enabled=False)
    legacy_factor(admin_engine, tenant, d, enabled=True)
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        listed = client.get(PEOPLE + "?state=all")
        assert listed.status_code == 200, listed.text
        rows = {row["principal_id"]: row["second_factor"] for row in listed.json()["people"]}
        assert {rows[str(x)] for x in (a, b)} == {True}
        assert {rows[str(x)] for x in (c, d)} == {False}
        for person, enrolled in ((a, True), (b, True), (c, False), (d, False)):
            detail = client.get(f"{PEOPLE}/{person}")
            assert detail.status_code == 200, detail.text
            assert detail.json()["person"]["second_factor"] is enrolled, person


def test_ak12_a_decision_carries_its_approval_and_execution(db, runtime, admin_engine, world):
    view = pending(runtime, world)
    with console_client(db, runtime, admin_engine, world["human"]) as approver:
        continuation = detail(approver, view.approval_id).json()["continuation"]
        assert decide(approver, view.approval_id, continuation).status_code == 200
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        history = client.get(f"{PEOPLE}/{world['human'].principal_id}").json()["history"]
        [decision] = history["decisions"]
        assert decision["approval_id"] == str(view.approval_id)
        assert decision["execution_id"] == str(view.execution_id)
        assert decision["approval"] == str(view.approval_id)[:8]


def test_ak12_a_decision_outside_a_narrowed_administrators_spaces_has_no_execution(
    db, runtime, admin_engine, world
):
    tenant = world["identity"].tenant_id
    view = pending(runtime, world)
    with console_client(db, runtime, admin_engine, world["human"]) as approver:
        continuation = detail(approver, view.approval_id).json()["continuation"]
        assert decide(approver, view.approval_id, continuation).status_code == 200
    narrowed = provision_identity(admin_engine, db, tenant, "ADMIN", world["clock"].now())
    with admin_engine.begin() as conn:
        own = default_space(conn, tenant)
        other = make_space(conn, tenant, "Customer B")
        seat(conn, tenant, own, narrowed.principal_id, "ADMIN")
        # The execution belongs to a space the narrowed administrator is not a member of.
        conn.execute(
            text(
                "UPDATE execbound.executions SET space_id = :s "
                "WHERE tenant_id = :t AND execution_id = :e"
            ),
            {"s": other, "t": tenant, "e": view.execution_id},
        )
    with console_client(db, runtime, admin_engine, narrowed) as client:
        answer = client.get(f"{PEOPLE}/{world['human'].principal_id}")
        assert answer.status_code == 200, answer.text
        [decision] = answer.json()["history"]["decisions"]
        assert decision["approval_id"] == str(view.approval_id)
        assert decision["execution_id"] is None
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        [decision] = client.get(f"{PEOPLE}/{world['human'].principal_id}").json()["history"][
            "decisions"
        ]
        assert decision["execution_id"] == str(view.execution_id)


def test_ak12_administrative_events_name_their_subjects_by_kind(db, runtime, admin_engine, world):
    tenant = world["identity"].tenant_id
    agent = world["identity"].principal_id
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        assert client.post(f"{API}/agents/{agent}/label", {"label": "Triage"}).status_code == 200
        person = client.post(PEOPLE, {"label": "Dana"}).json()["principal_id"]
        space = client.post(API + "/spaces", {"name": "Customer B"})
        assert space.status_code == 200, space.text
        issued = client.post(f"{API}/agents/{agent}/credentials/issue", {"lifetime": "8"})
        assert issued.status_code == 200, issued.text
        events = client.get(f"{PEOPLE}/{world['admin'].principal_id}").json()["history"]["events"]
    by_words = {}
    for event in events:
        by_words.setdefault(event["words"], event)
    issued_event = by_words["Issued credential"]
    assert issued_event["subject_kind"] == "credential"
    assert issued_event["subject_id"] == issued.json()["credential_id"]
    created_space = by_words["Created space"]
    assert created_space["subject_kind"] == "space" and created_space["subject_id"]
    labelled = [event for event in events if event["words"] == "Labelled"]
    kinds = {event["subject_id"]: event for event in labelled}
    assert kinds[str(agent)]["subject_kind"] == "principal"
    assert kinds[str(agent)]["subject_principal_kind"] == "AGENT"
    assert kinds[str(agent)]["subject_number"] == _number(admin_engine, agent)
    assert kinds[person]["subject_principal_kind"] == "HUMAN_APPROVER"
    activated = by_words["Activated policy bundle"]
    assert activated["subject_kind"] == "bundle"
    assert activated["subject_id"] == str(world["bundle"].bundle_id)
    # A payload value that is not an identifier is never shown.
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.audit_events SET payload = payload || "
                "jsonb_build_object('bundle_id', 'not-an-id') "
                "WHERE tenant_id = :t AND kind = 'policy.bundle_activated'"
            ),
            {"t": tenant},
        )
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        events = client.get(f"{PEOPLE}/{world['admin'].principal_id}").json()["history"]["events"]
    activated = next(event for event in events if event["words"] == "Activated policy bundle")
    assert activated["subject_id"] is None and activated["subject_kind"] is None
    assert activated["subject"] == ""


def _scopes(admin_engine, tenant, approver):
    with admin_engine.connect() as conn:
        return {
            (row.canonical_target_id, row.action, row.space_id)
            for row in conn.execute(
                text(
                    "SELECT canonical_target_id, action, space_id FROM execbound.approval_scopes "
                    "WHERE tenant_id = :t AND approver_id = :p AND active"
                ),
                {"t": tenant, "p": approver},
            )
        }


def test_assigning_a_scope_through_a_person_is_a_write_on_the_space(
    db, runtime, admin_engine, world
):
    """A scope assigned through `/people/{id}/scopes/...` is authorised as
    `/approvers/assign` authorises it: by the space it is written in, not by whether the
    administrator administers the person (#678). An administrator who also sits in another
    space as an approver assigns themselves to review in their own space, as Assign yourself
    does, and the person page they may not read answers no detail."""
    tenant = world["identity"].tenant_id
    canonical = str(world["canonical"])
    narrowed = provision_identity(admin_engine, db, tenant, "ADMIN", world["clock"].now())
    with admin_engine.begin() as conn:
        own = default_space(conn, tenant)
        other = make_space(conn, tenant, "Customer B")
        seat(conn, tenant, own, narrowed.principal_id, "ADMIN")
        seat(conn, tenant, other, narrowed.principal_id)
    me = str(narrowed.principal_id)
    with console_client(db, runtime, admin_engine, narrowed) as client:
        # Not someone this administrator administers: every seat is not one of their ADMIN
        # spaces, so the person page is not theirs to read.
        assert client.get(f"{PEOPLE}/{me}").status_code == 404
        # Looking at their own space, where an assignment lands.
        assert client.post(API + "/session/space", {"space_id": str(own)}).status_code == 200
        body = {"target": canonical, "action": "endpoint.lift_isolation"}
        assigned = client.post(f"{PEOPLE}/{me}/scopes/assign", body)
        assert assigned.status_code == 204, assigned.text
        assert assigned.content == b""
        assert (world["canonical"], "endpoint.lift_isolation", own) in _scopes(
            admin_engine, tenant, narrowed.principal_id
        )
        assert audit(admin_engine, tenant, "approval_scope.assigned")[-1]["approver_id"] == me
        unassigned = client.post(f"{PEOPLE}/{me}/scopes/unassign", body)
        assert unassigned.status_code == 204, unassigned.text
        assert not _scopes(admin_engine, tenant, narrowed.principal_id)
        # The same request through /approvers/assign lands the same way.
        through = client.post(API + "/approvers/assign", {"approver": me, **body})
        assert through.status_code == 200, through.text
        assert (world["canonical"], "endpoint.lift_isolation", own) in _scopes(
            admin_engine, tenant, narrowed.principal_id
        )
        # Still a human of this tenant: an agent, another tenant's or an unknown id is 404.
        for missing in (world["identity"].principal_id, uuid4()):
            refused = client.post(f"{PEOPLE}/{missing}/scopes/assign", body)
            assert refused.status_code == 404, missing
