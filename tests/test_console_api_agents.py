# SPDX-License-Identifier: AGPL-3.0-only
"""The Agents area of the console API (#333).

Every route through the harness: an administrator, an approver refused, a bearer credential
refused and audited, no session, a cross-tenant id answering 404, the secret check over every
response. Then the page's own behaviour as JSON: the three populations with their filters and
the cursor at fifty, a new agent, the detail's sections, a credential issued once under
`no-store` and revoked, deactivation felt at the gateway, binding from either side, and
`Govern this agent` all or nothing.
"""

from uuid import UUID, uuid4

import pytest
from console_api_fixtures import (
    API,
    assert_no_secrets,
    console_client,
    refusals,
)
from directory_fixtures import settle
from sample_fixtures import agent_identity, empty_workspace, offline_runtime
from sample_fixtures import sample_key as sample_key
from space_fixtures import default_space, make_space, place, seat
from sqlalchemy import text
from test_agents_bindings import BIND, LONG_NAME, binding_rows, new_agent_principal
from test_agents_bindings import found as found
from test_console_api_samples import ask, by_effect
from test_emergency_stop import audit
from test_execution import provision_identity
from test_execution import registry as registry
from test_execution import world as world
from test_human_surface import pending
from test_people_pages import call
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

from execbound import samples
from execbound.identity import AuthenticationFailed, authenticate
from execbound.policy.rulesets import ruleset_bundle
from execbound.policy.store import activate_bundle, create_bundle, validate_bundle
from execbound.replay.verify import reject_secrets
from execbound.surfaces.agents_pages import PAGE_SIZE
from execbound_harness.demo import ENDPOINT_RULESET

AGENTS = API + "/agents"
ZERO = "00000000-0000-0000-0000-000000000000"
# Every route with a well-formed body, so a refusal is the role's and not the body's.
ROUTES = [
    (AGENTS, "GET", None),
    (AGENTS, "POST", {"label": "x"}),
    (f"{AGENTS}/{ZERO}", "GET", None),
    (f"{AGENTS}/{ZERO}/label", "POST", {"label": "x"}),
    (f"{AGENTS}/{ZERO}/credentials/issue", "POST", {"lifetime": "8"}),
    (f"{AGENTS}/{ZERO}/credentials/{ZERO}/revoke", "POST", {}),
    (f"{AGENTS}/{ZERO}/deactivate", "POST", {"reason": "x"}),
    (f"{AGENTS}/{ZERO}/reactivate", "POST", {}),
    (f"{AGENTS}/{ZERO}/unbind", "POST", {"reason": "x"}),
    (f"{AGENTS}/{ZERO}/bind", "POST", {"target": ZERO}),
    (f"{AGENTS}/{ZERO}/govern", "POST", {"lifetime": "8"}),
]


def without_token(response):
    """The one secret a credential route returns, set aside; everything else is checked."""
    body = response.json()
    body.pop("token")
    reject_secrets(body)
    assert response.headers.get_list("set-cookie") == []
    return body


@pytest.mark.parametrize("path,method", [(path, method) for path, method, _ in ROUTES])
def test_every_route_refuses_a_bearer_and_no_session(
    db, runtime, seeded, admin_engine, world, path, method
):
    results = refusals(db, runtime, seeded, admin_engine, world, path, method)
    assert results["bearer"].status_code == 403 and results["bearer"].json()["code"] == "FORBIDDEN"
    assert results["audited"] == 1
    assert results["no_session"].status_code == 401
    assert results["no_session"].json()["code"] == "SESSION_REQUIRED"


def test_an_approver_is_refused_on_every_route(db, runtime, admin_engine, world):
    with console_client(db, runtime, admin_engine, world["human"]) as approver:
        for path, method, body in ROUTES:
            response = approver.get(path) if method == "GET" else approver.post(path, body)
            assert response.status_code == 403, (path, response.text)
            assert response.json()["code"] == "FORBIDDEN"
            assert_no_secrets(response)


def test_the_list_shows_three_populations_with_filters_and_the_month(
    db, runtime, admin_engine, world, found, seeded
):
    tenant, admin = world["identity"].tenant_id, world["admin"].principal_id
    first, second, third = (str(row["agent_id"]) for row in found["agents"])
    mine = str(world["identity"].principal_id)
    call(admin_engine, tenant, BIND, {"a": admin, "g": first, "p": mine})
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        page = client.get(AGENTS, params={"state": "all"})
        assert page.status_code == 200, page.text
        assert_no_secrets(page)
        body = page.json()
        rows = {row["row_id"]: row for row in body["agents"]}
        # The bound pair is one row addressed by its principal; the others by their agent.
        assert rows[mine]["population"] == "bound" and rows[mine]["agent_id"] == first
        assert first not in rows and rows[second]["population"] == "discovered"
        assert rows[third]["population"] == "discovered"
        assert (
            rows[mine]["name"] == "Synthetic agent 1" and rows[mine]["source"] == "entra_agent_id"
        )
        assert rows[second]["principal_id"] is None and rows[second]["sponsors"] == []
        assert str(world["human"].principal_id) not in rows
        assert body["active_month"] == 0 and body["month"].endswith("T00:00:00Z")
        assert body["line"]["sources"][0]["listed"] == 3 and body["line"]["bound"] == 1
        assert body["line"]["principals"] == 1
        assert [
            r["population"]
            for r in client.get(AGENTS, params={"population": "bound"}).json()["agents"]
        ] == ["bound"]
        only = client.get(AGENTS, params={"population": "discovered"}).json()["agents"]
        assert {row["row_id"] for row in only} == {second, third}
        assert client.get(AGENTS, params={"source": "tines"}).json()["agents"] == []
        # The month figure follows the kernel's own rows.
        settle(db, admin_engine, world, world["identity"], 1)
        active = client.get(AGENTS, params={"active": "yes"}).json()
        assert active["active_month"] == 1 and [r["row_id"] for r in active["agents"]] == [mine]
        assert active["agents"][0]["requests"] == 1 and active["agents"][0]["last_request"]
        assert client.get(AGENTS, params={"active": "no"}).json()["agents"] != []
        for bad in (
            {"state": "nope"},
            {"active": "maybe"},
            {"population": "everyone"},
            {"source": "okta"},
            {"ungoverned": "no"},
            {"foo": "1"},
            {"cursor": ""},
            {"cursor": "%%%"},
            {"cursor": "bm90"},
        ):
            refused = client.get(AGENTS, params=bad)
            assert refused.status_code == 400, bad
            assert refused.json()["code"] == "INVALID_REQUEST", bad
        # A cross-tenant principal is not in the list.
        assert str(seeded["principals"][1]) not in {
            row["row_id"] for row in client.get(AGENTS, params={"state": "all"}).json()["agents"]
        }


def test_the_list_pages_at_fifty_by_name_with_unnamed_last(db, runtime, admin_engine, world):
    tenant = world["identity"].tenant_id
    with admin_engine.begin() as conn:
        for index in range(PAGE_SIZE + 5):
            conn.execute(
                text(
                    "INSERT INTO execbound.principals (tenant_id, principal_id, kind, label, "
                    "space_id) "
                    "VALUES (:t, :p, 'AGENT', :l, "
                    "(SELECT space_id FROM execbound.spaces WHERE tenant_id = :t))"
                ),
                {"t": tenant, "p": uuid4(), "l": f"agent {index:03d}"},
            )
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        first = client.get(AGENTS).json()
        assert len(first["agents"]) == PAGE_SIZE and first["next"]
        assert first["agents"][0]["name"] == "agent 000"
        second = client.get(AGENTS, params={"cursor": first["next"]}).json()
        ids = {row["row_id"] for row in first["agents"]}
        assert not ids & {row["row_id"] for row in second["agents"]}
        assert second["agents"][-1]["row_id"] == str(world["identity"].principal_id)
        assert second["next"] is None


def test_registered_agents_filter_before_pagination_and_keep_their_population(
    db, runtime, admin_engine, world, found
):
    tenant, admin = world["identity"].tenant_id, world["admin"].principal_id
    mine = str(world["identity"].principal_id)
    discovered = {str(row["agent_id"]) for row in found["agents"]}
    bound_agent = str(found["agents"][0]["agent_id"])
    call(admin_engine, tenant, BIND, {"a": admin, "g": bound_agent, "p": mine})
    principals = [uuid4() for _ in range(PAGE_SIZE + 5)]
    with admin_engine.begin() as conn:
        for index, principal in enumerate(principals):
            conn.execute(
                text(
                    "INSERT INTO execbound.principals (tenant_id, principal_id, kind, label, "
                    "space_id) VALUES (:t, :p, 'AGENT', :l, "
                    "(SELECT space_id FROM execbound.spaces WHERE tenant_id = :t))"
                ),
                {"t": tenant, "p": principal, "l": f"zz registered {index:03d}"},
            )
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        # These discoveries sort before the registered agents. Filtering a page in the
        # browser would lose entries and would not yield a full page of registered agents.
        unfiltered = client.get(AGENTS).json()["agents"]
        assert any(row["principal_id"] is None for row in unfiltered)
        first_response = client.get(AGENTS, params={"population": "registered"})
        assert first_response.status_code == 200, first_response.text
        assert_no_secrets(first_response)
        first = first_response.json()
        assert len(first["agents"]) == PAGE_SIZE and first["next"]
        second_response = client.get(
            AGENTS, params={"population": "registered", "cursor": first["next"]}
        )
        assert second_response.status_code == 200, second_response.text
        assert_no_secrets(second_response)
        second = second_response.json()
        assert second["next"] is None
        rows = first["agents"] + second["agents"]
        ids = [row["row_id"] for row in rows]
        assert len(ids) == len(set(ids)) == len(principals) + 1
        assert set(ids) == {mine, *(str(principal) for principal in principals)}
        assert not set(ids) & discovered
        assert all(row["principal_id"] == row["row_id"] for row in rows)
        assert {row["row_id"]: row["population"] for row in rows} == {
            mine: "bound",
            **{str(principal): "governed" for principal in principals},
        }


def test_a_new_agent_needs_a_label_and_the_detail_has_its_sections(
    db, runtime, admin_engine, world, seeded
):
    tenant = world["identity"].tenant_id
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        blank = client.post(AGENTS, {"label": "   "})
        assert blank.status_code == 400 and blank.json() == {
            "code": "INVALID_BODY",
            "detail": "The body has a field that is missing, unknown or out of bounds.",
            "fields": ["label"],
        }
        assert client.post(AGENTS, {"label": "x" * 81}).json()["fields"] == ["label"]
        assert client.post(AGENTS, {"label": "a", "kind": "ADMIN"}).json()["fields"] == ["kind"]
        made = client.post(AGENTS, {"label": "  Triage bot  "})
        assert made.status_code == 200, made.text
        principal = made.json()["principal_id"]
        assert audit(admin_engine, tenant, "principal.labelled")[-1]["label"] == "Triage bot"
        detail = client.get(f"{AGENTS}/{principal}")
        assert detail.status_code == 200, detail.text
        assert_no_secrets(detail)
        body = detail.json()
        assert body["kind"] == "principal" and body["row_id"] == principal
        assert body["agent"]["label"] == "Triage bot" and body["agent"]["active"]
        assert body["binding"] is None and body["discovered"] is None
        assert body["credentials"] == [] and body["recent"] == [] and body["runs"] == []
        assert body["requests"] == 0 and body["bundle"] and body["options"] == []
        # The active bundle governs one action; nothing executed, so the row is inferred.
        assert [(row["action"], row["certainty"]) for row in body["reach"]] == [
            ("endpoint.isolate", "inferred")
        ]
        assert body["reach"][0]["path"] == "ExecBound, this agent's credentials"
        relabelled = client.post(f"{AGENTS}/{principal}/label", {"label": "Triage"})
        assert relabelled.status_code == 200 and relabelled.json()["agent"]["label"] == "Triage"
        assert client.post(f"{AGENTS}/{principal}/label", {"label": " "}).json()["fields"] == [
            "label"
        ]
        # Unknown, malformed, cross-tenant and human ids answer 404 alike.
        for missing in (uuid4(), seeded["principals"][1], world["human"].principal_id):
            assert client.get(f"{AGENTS}/{missing}").status_code == 404, missing
            assert client.post(f"{AGENTS}/{missing}/label", {"label": "x"}).status_code == 404
        assert client.get(f"{AGENTS}/not-an-id").json()["code"] == "NOT_FOUND"
        assert client.get(f"{AGENTS}/{str(uuid4()).upper()}").status_code == 404


def test_a_reach_row_names_the_rules_the_active_bundle_holds_for_its_action(
    db, runtime, admin_engine, world
):
    """#273: what the rules say about each governed path, carried as data.

    The names and their effects stay apart, with the bundle they are in beside them, so the
    page prints the effect as a word and links the name to the rules page rather than taking
    an address out of a sentence. A reading is not a decision: the kernel decides from the
    compiled bundle over attested facts, and a rule sees no limit, quorum or approval.
    """
    mine = str(world["identity"].principal_id)
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        # The world's own bundle is the endpoint seed written as a document: since #678 the
        # agent page recognises it, as the policy page does, and names its rules.
        plain = client.get(f"{AGENTS}/{mine}").json()
        assert plain["rules_bundle_id"] == str(world["bundle"].bundle_id)
        assert plain["rules_origin"] == "recognized-seed"
        assert all(row["rules"] for row in plain["reach"])

        content = ruleset_bundle(
            ENDPOINT_RULESET,
            tenant_id=world["identity"].tenant_id,
            bundle_id=uuid4(),
            mappings=world["bundle"].mappings,
        )
        create_bundle(db, world["admin"], content, world["clock"])
        validate_bundle(db, world["admin"], content.bundle_id, world["clock"])
        activate_bundle(db, world["admin"], content.bundle_id, world["clock"])

        body = client.get(f"{AGENTS}/{mine}").json()
        assert body["rules_bundle_id"] == str(content.bundle_id)
        row = next(row for row in body["reach"] if row["action"] == "endpoint.isolate")
        # In the order the compiler writes them, so the column never reshuffles on its own.
        assert [{"id": rule["id"], "effect": rule["effect"]} for rule in row["rules"]] == [
            {"id": "isolate-workstation-open-critical", "effect": "allow"},
            {"id": "isolate-never-criticality-4", "effect": "deny"},
            {"id": "isolate-never-domain-controller", "effect": "deny"},
            {"id": "isolate-production-needs-review", "effect": "review"},
        ]
        # The names are the ruleset's own, which is what the rules page of that bundle reads.
        rules = client.get(f"{API}/policy/{content.bundle_id}/rules")
        assert rules.status_code == 200, rules.text
        group = next(
            group for group in rules.json()["groups"] if group["action"] == "endpoint.isolate"
        )
        assert [rule["id"] for rule in group["rules"]] == [rule["id"] for rule in row["rules"]]
        assert_no_secrets(client.get(f"{AGENTS}/{mine}"))


def test_the_limits_read_the_ledger_the_way_admission_counts(db, runtime, admin_engine, world):
    mine = str(world["identity"].principal_id)
    settle(db, admin_engine, world, world["identity"], 2)
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        body = client.get(f"{AGENTS}/{mine}").json()
        assert body["requests"] == 2 and len(body["recent"]) == 2
        assert body["recent"][0]["state"] == "EXECUTED"
        assert body["recent"][0]["label"] and body["recent"][0]["action"] == "endpoint.isolate"
        assert body["reach"][0]["certainty"] == "verified"
        assert body["limits"], "the world's bundle carries a limit rule"
        for row in body["limits"]:
            assert row["max_targets"] > 0 and row["window"] and row["on_exceed"]
            assert row["count"] is None or row["count"] >= 0


def test_a_credential_is_issued_once_under_no_store_and_revoked(db, runtime, admin_engine, world):
    mine = str(world["identity"].principal_id)
    tenant = world["identity"].tenant_id
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        assert client.post(f"{AGENTS}/{mine}/credentials/issue", {"lifetime": "9"}).json()[
            "fields"
        ] == ["lifetime"]
        issued = client.post(f"{AGENTS}/{mine}/credentials/issue", {"lifetime": "8"})
        assert issued.status_code == 200, issued.text
        assert issued.headers["cache-control"] == "no-store"
        body = without_token(issued)
        token = issued.json()["token"]
        assert token.startswith("eb1.") and body["kind"] == "AGENT"
        assert body["principal_id"] == mine
        assert authenticate(runtime.db, token).principal_id == world["identity"].principal_id
        credential = body["credential_id"]
        assert audit(admin_engine, tenant, "credential.issued")[-1]["credential_id"] == credential
        detail = client.get(f"{AGENTS}/{mine}")
        assert_no_secrets(detail)
        assert token not in detail.text
        rows = {row["credential_id"]: row for row in detail.json()["credentials"]}
        assert rows[credential]["state"] == "live" and rows[credential]["failures"] == 0
        # A credential of another principal cannot be revoked under this agent's path.
        with admin_engine.connect() as conn:
            other = str(
                conn.execute(
                    text(
                        "SELECT credential_id FROM execbound.credentials "
                        "WHERE tenant_id = :t AND principal_id = :p"
                    ),
                    {"t": tenant, "p": world["human"].principal_id},
                ).scalar_one()
            )
        assert client.post(f"{AGENTS}/{mine}/credentials/{other}/revoke", {}).status_code == 404
        revoked = client.post(f"{AGENTS}/{mine}/credentials/{credential}/revoke", {})
        assert revoked.status_code == 200, revoked.text
        assert_no_secrets(revoked)
        rows = {row["credential_id"]: row for row in revoked.json()["credentials"]}
        assert rows[credential]["state"] == "revoked"
        with pytest.raises(AuthenticationFailed):
            authenticate(runtime.db, token)
        again = client.post(f"{AGENTS}/{mine}/credentials/{credential}/revoke", {})
        assert again.status_code == 409 and again.json()["code"] == "CONFLICT"
        assert client.post(f"{AGENTS}/{mine}/credentials/{credential}/revoke", {"x": 1}).json()[
            "fields"
        ] == ["x"]


def _keys(admin_engine, tenant, principal):
    with admin_engine.connect() as conn:
        return {
            row.credential_id: row
            for row in conn.execute(
                text(
                    "SELECT credential_id, revoked_at, replaces_credential_id, last_used_at "
                    "FROM execbound.credentials WHERE tenant_id = :t AND principal_id = :p"
                ),
                {"t": tenant, "p": principal},
            )
        }


def _spoil(admin_engine, tenant, credential, column, value="now()"):
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                f"UPDATE execbound.credentials SET {column} = {value} "  # nosec B608 - test
                "WHERE tenant_id = :t AND credential_id = :c"
            ),
            {"t": tenant, "c": credential},
        )


def test_ak5_ak6_an_issue_with_replaces_records_the_rotation_and_refuses_the_rest(
    db, runtime, admin_engine, world
):
    """The agent issue route's `replaces`: a live key of this agent is named in the same
    transaction as the issue, and anything else is refused 409 with nothing issued."""
    tenant = world["identity"].tenant_id
    mine = world["identity"].principal_id
    old = world["identity"].credential_id
    issue_path = f"{AGENTS}/{mine}/credentials/issue"
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        made = client.post(AGENTS, {"label": "Other"})
        other = made.json()["principal_id"]
        others = client.post(f"{AGENTS}/{other}/credentials/issue", {"lifetime": "8"}).json()
        spent = without_token(client.post(issue_path, {"lifetime": "8"}))["credential_id"]
        assert client.post(f"{AGENTS}/{mine}/credentials/{spent}/revoke", {}).status_code == 200
        lapsed = without_token(client.post(issue_path, {"lifetime": "1"}))["credential_id"]
        _spoil(admin_engine, tenant, lapsed, "expires_at", "now() - interval '1 minute'")

        before = _keys(admin_engine, tenant, mine)
        for replaced in (others["credential_id"], spent, lapsed):
            refused = client.post(issue_path, {"lifetime": "8", "replaces": replaced})
            assert refused.status_code == 409, (replaced, refused.text)
            assert refused.json()["code"] == "CONFLICT"
            assert "token" not in refused.json()
        assert _keys(admin_engine, tenant, mine).keys() == before.keys()

        not_uuid = client.post(issue_path, {"lifetime": "8", "replaces": "not-a-uuid"})
        assert not_uuid.status_code == 400
        assert not_uuid.json()["code"] == "INVALID_BODY"
        assert not_uuid.json()["fields"] == ["replaces"]
        assert client.post(issue_path, {"lifetime": "8", "replace": str(old)}).json()["fields"] == [
            "replace"
        ]

        rotated = client.post(issue_path, {"lifetime": "720", "replaces": str(old)})
        assert rotated.status_code == 200, rotated.text
        body = without_token(rotated)
        new = body["credential_id"]
        keys = _keys(admin_engine, tenant, mine)
        assert str(keys[UUID(new)].replaces_credential_id) == str(old)
        assert keys[old].revoked_at is None
        event = audit(admin_engine, tenant, "credential.issued")[-1]
        assert event["credential_id"] == new and event["replaces"] == str(old)

        # A key a live key already names cannot be named again.
        again = client.post(issue_path, {"lifetime": "8", "replaces": str(old)})
        assert again.status_code == 409 and again.json()["code"] == "CONFLICT"
        assert len(_keys(admin_engine, tenant, mine)) == len(keys)

        plain = without_token(client.post(issue_path, {"lifetime": "8"}))
        event = audit(admin_engine, tenant, "credential.issued")[-1]
        assert event["credential_id"] == plain["credential_id"]
        assert set(event) == {
            "credential_id",
            "principal_id",
            "kind",
            "expires_at",
            "actor_credential_id",
        }

        detail = client.get(f"{AGENTS}/{mine}").json()
        rows = {row["credential_id"]: row for row in detail["credentials"]}
        assert rows[str(old)]["replaced"] is True
        assert rows[new]["replaced"] is False
        assert "last_used_at" in rows[new]
        # The world's key authenticated as the fixtures were built.
        assert rows[str(old)]["last_used_at"] is not None


def test_deactivation_is_felt_at_the_gateway_and_reactivation_issues_nothing(
    db, runtime, admin_engine, world
):
    mine = str(world["identity"].principal_id)
    tenant = world["identity"].tenant_id
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        token = client.post(f"{AGENTS}/{mine}/credentials/issue", {"lifetime": "8"}).json()["token"]
        assert client.post(f"{AGENTS}/{mine}/deactivate", {"reason": ""}).json()["fields"] == [
            "reason"
        ]
        # An administrator or an approver is not an agent, so the route never sees them.
        for human in (world["admin"], world["human"]):
            refused = client.post(f"{AGENTS}/{human.principal_id}/deactivate", {"reason": "x"})
            assert refused.status_code == 404, human.kind
        gone = client.post(f"{AGENTS}/{mine}/deactivate", {"reason": "left the team"})
        assert gone.status_code == 200, gone.text
        assert_no_secrets(gone)
        body = gone.json()
        assert not body["agent"]["active"] and body["agent"]["deactivated_at"]
        assert all(row["state"] == "revoked" for row in body["credentials"])
        with pytest.raises(AuthenticationFailed):
            authenticate(runtime.db, token)
        event = audit(admin_engine, tenant, "principal.deactivated")[-1]
        assert event["reason"] == "left the team" and event["credentials_revoked"] >= 1
        assert event["sessions_revoked"] == 0
        again = client.post(f"{AGENTS}/{mine}/deactivate", {"reason": "twice"})
        assert again.status_code == 409 and again.json()["code"] == "CONFLICT"
        # A deactivated agent is given no credential.
        refused = client.post(f"{AGENTS}/{mine}/credentials/issue", {"lifetime": "8"})
        assert refused.status_code == 400 and refused.json()["code"] == "INVALID_PRINCIPAL"
        assert "token" not in refused.json()
        assert mine not in {row["row_id"] for row in client.get(AGENTS).json()["agents"]}
        listed = client.get(AGENTS, params={"state": "deactivated"}).json()["agents"]
        assert [row["row_id"] for row in listed] == [mine] and listed[0]["active"] is False
        back = client.post(f"{AGENTS}/{mine}/reactivate", {})
        assert back.status_code == 200 and back.json()["agent"]["active"]
        assert all(row["state"] == "revoked" for row in back.json()["credentials"])
        assert client.post(f"{AGENTS}/{mine}/reactivate", {}).status_code == 409
        assert audit(admin_engine, tenant, "principal.reactivated")[-1]["principal_id"] == mine


def test_binding_from_either_side_and_unbinding_with_a_reason(
    db, runtime, admin_engine, world, found
):
    tenant = world["identity"].tenant_id
    first, second, _ = (str(row["agent_id"]) for row in found["agents"])
    mine = str(world["identity"].principal_id)
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        # A governed principal offers the unbound discovered agents; a discovered agent offers
        # the unbound principals.
        governed = client.get(f"{AGENTS}/{mine}").json()
        assert {option["id"] for option in governed["options"]} == {first, second} | {
            str(found["agents"][2]["agent_id"])
        }
        discovered = client.get(f"{AGENTS}/{second}").json()
        assert discovered["kind"] == "discovered" and discovered["agent"] is None
        assert discovered["discovered"]["agent"]["display_name"] == "Synthetic agent 2"
        assert discovered["discovered"]["agent"]["platform_ref"]
        assert [option["id"] for option in discovered["options"]] == [mine]
        assert client.post(f"{AGENTS}/{mine}/bind", {"target": "nope"}).json()["fields"] == [
            "target"
        ]
        bound = client.post(f"{AGENTS}/{mine}/bind", {"target": first})
        assert bound.status_code == 200, bound.text
        assert_no_secrets(bound)
        body = bound.json()
        assert body["row_id"] == mine and body["binding"]["agent_id"] == first
        assert body["binding"]["bound_by"] == str(world["admin"].principal_id)
        assert body["discovered"]["agent"]["display_name"] == "Synthetic agent 1"
        assert body["options"] == []
        assert audit(admin_engine, tenant, "agent.bound")[-1]["principal_id"] == mine
        # The bound agent's own id answers with its principal's detail.
        moved = client.get(f"{AGENTS}/{first}").json()
        assert moved["row_id"] == mine and moved["kind"] == "principal"
        # Binding again from either side is refused as a conflict.
        assert client.post(f"{AGENTS}/{first}/bind", {"target": mine}).status_code == 409
        assert client.post(f"{AGENTS}/{mine}/bind", {"target": second}).status_code == 409
        assert client.post(f"{AGENTS}/{second}/bind", {"target": mine}).status_code == 409
        assert client.post(f"{AGENTS}/{mine}/unbind", {"reason": " "}).json()["fields"] == [
            "reason"
        ]
        released = client.post(f"{AGENTS}/{mine}/unbind", {"reason": "wrong agent"})
        assert released.status_code == 200 and released.json()["binding"] is None
        assert audit(admin_engine, tenant, "agent.unbound")[-1]["reason"] == "wrong agent"
        assert client.post(f"{AGENTS}/{mine}/unbind", {"reason": "again"}).status_code == 409
        assert client.get(f"{AGENTS}/{first}").json()["kind"] == "discovered"


def test_govern_this_agent_creates_binds_and_issues_once_with_what_to_do_next(
    db, runtime, admin_engine, world, found
):
    tenant = world["identity"].tenant_id
    target = str(found["agents"][2]["agent_id"])
    mine = str(world["identity"].principal_id)
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        assert client.post(f"{AGENTS}/{target}/govern", {"lifetime": "0"}).json()["fields"] == [
            "lifetime"
        ]
        governed = client.post(f"{AGENTS}/{target}/govern", {"lifetime": "8"})
        assert governed.status_code == 200, governed.text
        assert governed.headers["cache-control"] == "no-store"
        body = without_token(governed)
        token = governed.json()["token"]
        identity = authenticate(runtime.db, token)
        assert identity.kind == "AGENT" and str(identity.principal_id) == body["principal_id"]
        principal = body["principal_id"]
        steps = body["next_steps"]
        assert "pipx install" in steps["install"] and "claude mcp add" in steps["mcp"]
        assert token not in steps["install"] and token not in steps["mcp"]
        assert "http://127.0.0.1" in steps["mcp"]
        [row] = binding_rows(admin_engine, tenant)
        assert str(row["agent_id"]) == target and str(row["principal_id"]) == principal
        labelled = audit(admin_engine, tenant, "principal.labelled")[-1]
        assert labelled["label"] == LONG_NAME[:80].strip()
        for kind in ("principal.created", "agent.bound", "credential.issued"):
            assert audit(admin_engine, tenant, kind)[-1]["principal_id"] == principal, kind
        detail = client.get(f"{AGENTS}/{target}")
        assert detail.json()["row_id"] == principal and token not in detail.text
        assert detail.json()["agent"]["label"] == LONG_NAME[:80].strip()
        # Governing an agent that is governed, or a principal, issues nothing.
        for subject in (target, principal, mine):
            again = client.post(f"{AGENTS}/{subject}/govern", {"lifetime": "8"})
            assert again.status_code == 409 and "token" not in again.json(), subject
        assert len(binding_rows(admin_engine, tenant)) == 1
        assert client.post(f"{AGENTS}/{uuid4()}/govern", {"lifetime": "8"}).status_code == 404


def test_govern_this_agent_is_all_or_nothing(db, runtime, admin_engine, world, found):
    tenant = world["identity"].tenant_id
    target = str(found["agents"][1]["agent_id"])

    def counts():
        with admin_engine.connect() as conn:
            return conn.execute(
                text(
                    "SELECT (SELECT count(*) FROM execbound.principals WHERE tenant_id = :t), "
                    "(SELECT count(*) FROM execbound.credentials WHERE tenant_id = :t), "
                    "(SELECT count(*) FROM execbound.agent_bindings WHERE tenant_id = :t), "
                    "(SELECT count(*) FROM execbound.audit_events WHERE tenant_id = :t)"
                ),
                {"t": tenant},
            ).one()

    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        assert client.get(f"{AGENTS}/{target}").status_code == 200
        before = counts()
        # The source drops the agent between the page load and the request: the principal
        # and its label are written before the bind is refused, and all of it rolls back.
        with admin_engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE execbound.monitor_agents SET gone_at = observed_at WHERE agent_id = :a"
                ),
                {"a": target},
            )
        refused = client.post(f"{AGENTS}/{target}/govern", {"lifetime": "8"})
        assert refused.status_code == 409 and refused.json()["code"] == "CONFLICT"
        assert "token" not in refused.json()
        assert counts() == before


def test_hf50_the_line_carries_the_limit_the_count_and_dormancy(db, runtime, admin_engine, world):
    """The Agents page's line carries the workspace's agent limit (`tenants.max_agents`, #257)
    and the count the cap makes. `agents_held` counts live and sleeping AGENT principals,
    exactly as the cap does; a workspace with no limit (the default every tenant is born with)
    carries no `agent_limit` for the line to show.
    """
    tenant = world["identity"].tenant_id
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        page = client.get(AGENTS)
        assert page.status_code == 200, page.text
        assert_no_secrets(page)
        line = page.json()["line"]
        assert "plan" not in line
        assert line["agent_limit"] is None
        assert line["agents_held"] == 1  # world["identity"] alone
        assert line["agents_dormant"] == 0

    sleeping = new_agent_principal(admin_engine, tenant)
    new_agent_principal(admin_engine, tenant)
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.tenants SET max_agents = 3 WHERE tenant_id = :t"), {"t": tenant}
        )
        conn.execute(
            text(
                "UPDATE execbound.principals SET active = false, dormant_at = now() "
                "WHERE tenant_id = :t AND principal_id = :p"
            ),
            {"t": tenant, "p": sleeping},
        )
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        line = client.get(AGENTS).json()["line"]
        assert "plan" not in line
        assert line["agent_limit"] == 3
        # A sleeping agent still counts against the cap, because its setup is reserved.
        assert line["agents_held"] == 3
        assert line["agents_dormant"] == 1


def test_hf52_the_row_and_the_detail_tell_asleep_from_deactivated(db, runtime, admin_engine, world):
    """Hosted Free (#439): the row and the detail must say which is which.

    A sleeping agent still counts against the cap; a hand-deactivated one frees its
    allowance. The console can't ask a person to "open an agent marked Asleep" (the capacity
    line's own promise) unless the row and the detail both carry that fact, not just
    `active`, which reads identically for both.
    """
    tenant = world["identity"].tenant_id
    mine = str(world["identity"].principal_id)  # live
    sleeping = new_agent_principal(admin_engine, tenant)
    deactivated = new_agent_principal(admin_engine, tenant)
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.principals SET active = false, dormant_at = now() "
                "WHERE tenant_id = :t AND principal_id = :p"
            ),
            {"t": tenant, "p": sleeping},
        )
    call(
        admin_engine,
        tenant,
        "SELECT execbound.admin_deactivate_principal(:a, :p, :r)",
        {"a": world["admin"].principal_id, "p": deactivated, "r": "no longer needed"},
    )
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        page = client.get(AGENTS, params={"state": "all"})
        assert page.status_code == 200, page.text
        assert_no_secrets(page)
        rows = {row["row_id"]: row for row in page.json()["agents"]}
        assert rows[mine]["active"] is True and rows[mine]["dormant"] is False
        assert rows[str(sleeping)]["active"] is False
        assert rows[str(sleeping)]["dormant"] is True
        assert rows[str(deactivated)]["active"] is False
        assert rows[str(deactivated)]["dormant"] is False

        sleeping_page = client.get(f"{AGENTS}/{sleeping}")
        assert_no_secrets(sleeping_page)
        sleeping_agent = sleeping_page.json()["agent"]
        assert sleeping_agent["active"] is False and sleeping_agent["dormant"] is True

        deactivated_agent = client.get(f"{AGENTS}/{deactivated}").json()["agent"]
        assert deactivated_agent["active"] is False and deactivated_agent["dormant"] is False


def test_ux16_the_page_counts_the_asleep_agents_of_the_space_it_lists(
    db, runtime, admin_engine, world
):
    """The list's empty-Space test (UX16, #439) asks whether the Space it lists holds an asleep
    agent, which the default State hides. The tenant line's `agents_dormant` is the whole
    workspace's, so the page carries `space_dormant`, counted under the list's own Space
    predicate and whatever its filters: a Space with no agent reads 0 while another Space's
    agent sleeps, and reads as a Space with no agents rather than as one filtered out.
    """
    tenant = world["identity"].tenant_id
    sleeping = new_agent_principal(admin_engine, tenant)
    with admin_engine.begin() as conn:
        own = default_space(conn, tenant)
        empty = make_space(conn, tenant, "Customer B")
        conn.execute(
            text(
                "UPDATE execbound.principals SET active = false, dormant_at = now() "
                "WHERE tenant_id = :t AND principal_id = :p"
            ),
            {"t": tenant, "p": sleeping},
        )
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        assert client.post(f"{API}/session/space", {"space_id": str(empty)}).status_code == 200
        page = client.get(AGENTS)
        assert page.status_code == 200, page.text
        body = page.json()
        assert body["agents"] == []
        assert body["line"]["agents_dormant"] == 1
        assert body["space_dormant"] == 0
        assert client.post(f"{API}/session/space", {"space_id": str(own)}).status_code == 200
        assert client.get(AGENTS).json()["space_dormant"] == 1
        assert client.get(AGENTS, params={"population": "discovered"}).json()["space_dormant"] == 1
        assert client.post(f"{API}/session/space", {"space_id": None}).status_code == 200
        assert client.get(AGENTS).json()["space_dormant"] == 1


def test_cf8_a_binding_names_who_made_it(db, runtime, admin_engine, world, found):
    """The binding names the administrator who made it by kind and number (#678), on the bind's
    own answer and on the next read; the UUID stays beside it."""
    first = str(found["agents"][0]["agent_id"])
    mine = str(world["identity"].principal_id)
    admin_id = str(world["admin"].principal_id)
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        bound = client.post(f"{AGENTS}/{mine}/bind", {"target": first})
        assert bound.status_code == 200, bound.text
        for body in (bound.json(), client.get(f"{AGENTS}/{mine}").json()):
            binding = body["binding"]
            assert binding["bound_by"] == admin_id
            ref = binding["bound_by_ref"]
            assert (ref["principal_id"], ref["kind"], ref["number"]) == (admin_id, "ADMIN", 1)


def _sampled(db, admin_engine, sample_key):
    workspace = empty_workspace(admin_engine, db)
    installed = samples.install(db, workspace.admin, available=True)
    return workspace, installed, agent_identity(admin_engine, db, workspace)


def _reference(admin_engine, tenant, execution):
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        number = conn.execute(
            text(
                "SELECT request_number FROM execbound.executions "
                "WHERE tenant_id = :t AND execution_id = :e"
            ),
            {"t": tenant, "e": execution},
        ).scalar_one()
    return f"EB-{number}"


def test_recent_rows_carry_their_request_reference(db, admin_engine, seeded, sample_key):
    workspace, installed, agent = _sampled(db, admin_engine, sample_key)
    asked = ask(db, agent, by_effect(installed)["deny"], "sample-dc")
    with console_client(
        db, offline_runtime(db, sample_key), admin_engine, workspace.admin
    ) as admin:
        response = admin.get(f"{AGENTS}/{agent.principal_id}")
    assert response.status_code == 200, response.text
    assert_no_secrets(response)
    recent = response.json()["recent"]
    assert [(row["execution_id"], row["request_ref"]) for row in recent] == [
        (
            str(asked.view.execution_id),
            _reference(admin_engine, workspace.tenant_id, asked.view.execution_id),
        )
    ]


def test_the_agents_list_names_each_agents_newest_request(db, admin_engine, seeded, sample_key):
    workspace, installed, agent = _sampled(db, admin_engine, sample_key)
    quiet = agent_identity(admin_engine, db, workspace)
    ask(db, agent, by_effect(installed)["deny"], "sample-dc")
    newest = ask(db, agent, by_effect(installed)["allow"], "sample-dev")
    with console_client(
        db, offline_runtime(db, sample_key), admin_engine, workspace.admin
    ) as admin:
        response = admin.get(AGENTS, params={"state": "all"})
    assert response.status_code == 200, response.text
    rows = {row["row_id"]: row for row in response.json()["agents"]}
    busy = rows[str(agent.principal_id)]
    assert busy["last_execution_id"] == str(newest.view.execution_id)
    assert busy["last_request_ref"] == _reference(
        admin_engine, workspace.tenant_id, newest.view.execution_id
    )
    idle = rows[str(quiet.principal_id)]
    assert (idle["last_execution_id"], idle["last_request_ref"]) == (None, None)


def test_the_newest_request_is_read_in_the_current_space(db, admin_engine, seeded, sample_key):
    workspace, installed, agent = _sampled(db, admin_engine, sample_key)
    first = ask(db, agent, by_effect(installed)["deny"], "sample-dc")
    moved = ask(db, agent, by_effect(installed)["allow"], "sample-dev")
    tenant = workspace.tenant_id
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        second = make_space(conn, tenant, "Customer B")
        place(conn, tenant, "executions", "execution_id", moved.view.execution_id, second)
    with console_client(
        db, offline_runtime(db, sample_key), admin_engine, workspace.admin
    ) as admin:
        assert (
            admin.post(API + "/session/space", {"space_id": str(workspace.space_id)}).status_code
            == 200
        )
        rows = {row["row_id"]: row for row in admin.get(AGENTS).json()["agents"]}
    row = rows[str(agent.principal_id)]
    assert row["last_execution_id"] == str(first.view.execution_id)
    assert row["last_request_ref"] == _reference(admin_engine, tenant, first.view.execution_id)


# The agent page's rules and activity (#678, AK8), and its controls for a reader who sees an
# agent without administering it.


def test_ak8_a_recognised_seed_reads_as_rules_and_keeps_its_exact_text(
    db, runtime, admin_engine, world
):
    mine = str(world["identity"].principal_id)
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        # The world's bundle is the endpoint seed written as Cedar: the policy page reads it as
        # rules, and so does the agent page now, while still sending the exact documents.
        seed = client.get(f"{AGENTS}/{mine}").json()
        assert seed["rules_origin"] == "recognized-seed"
        assert seed["rules_bundle_id"] == str(world["bundle"].bundle_id)
        [row] = [row for row in seed["reach"] if row["action"] == "endpoint.isolate"]
        assert row["rules"] and all(rule["description"] for rule in row["rules"])
        assert seed["policy_document"] is not None
        assert "forbid" in seed["policy_document"]["authorization_policies"]

        written = ruleset_bundle(
            ENDPOINT_RULESET,
            tenant_id=world["identity"].tenant_id,
            bundle_id=uuid4(),
            mappings=world["bundle"].mappings,
        )
        create_bundle(db, world["admin"], written, world["clock"])
        validate_bundle(db, world["admin"], written.bundle_id, world["clock"])
        activate_bundle(db, world["admin"], written.bundle_id, world["clock"])
        rules = client.get(f"{AGENTS}/{mine}").json()
        assert rules["rules_origin"] == "rules" and rules["policy_document"] is None
        assert rules["rules_bundle_id"] == str(written.bundle_id)

        custom = world["bundle"].model_copy(
            update={
                "bundle_id": uuid4(),
                "authorization_policies": world["bundle"].authorization_policies
                + "\nforbid(principal, action, resource) when { false };\n",
            }
        )
        create_bundle(db, world["admin"], custom, world["clock"])
        validate_bundle(db, world["admin"], custom.bundle_id, world["clock"])
        activate_bundle(db, world["admin"], custom.bundle_id, world["clock"])
        cedar = client.get(f"{AGENTS}/{mine}").json()
        assert cedar["rules_origin"] is None and cedar["rules_bundle_id"] is None
        assert cedar["policy_document"] is not None
        assert [row["rules"] for row in cedar["reach"]] == [[]]


def test_ak8_recent_rows_name_their_target(db, runtime, admin_engine, world):
    mine = str(world["identity"].principal_id)
    tenant = world["identity"].tenant_id
    pending(runtime, world)
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        [recent] = client.get(f"{AGENTS}/{mine}").json()["recent"]
        assert recent["target_label"] == "device-01"
        with admin_engine.begin() as conn:
            conn.execute(
                text("DELETE FROM execbound.resource_identities WHERE tenant_id = :t"),
                {"t": tenant},
            )
        [recent] = client.get(f"{AGENTS}/{mine}").json()["recent"]
        assert recent["target_label"] is None


def test_an_agent_the_reader_sees_but_does_not_administer_says_so(db, runtime, admin_engine, world):
    """An administrator seated as an approver in another space reads that space's agents and
    administers none of them (#678): the detail says which, so the page offers no change the
    server would answer 404."""
    tenant = world["identity"].tenant_id
    narrowed = provision_identity(admin_engine, db, tenant, "ADMIN", world["clock"].now())
    with admin_engine.begin() as conn:
        own = default_space(conn, tenant)
        other = make_space(conn, tenant, "Customer B")
        seat(conn, tenant, own, narrowed.principal_id, "ADMIN")
        seat(conn, tenant, other, narrowed.principal_id)
        conn.execute(
            text(
                "UPDATE execbound.principals SET space_id = :s "
                "WHERE tenant_id = :t AND principal_id = :p"
            ),
            {"s": other, "t": tenant, "p": world["identity"].principal_id},
        )
    theirs = str(world["identity"].principal_id)
    with console_client(db, runtime, admin_engine, narrowed) as client:
        made = client.post(f"{API}/session/space", {"space_id": str(own)})
        assert made.status_code == 200
        mine = client.post(AGENTS, {"label": "Own agent"}).json()["principal_id"]
        assert client.post(f"{API}/session/space", {"space_id": None}).status_code == 200
        seen = client.get(f"{AGENTS}/{theirs}")
        assert seen.status_code == 200, seen.text
        assert seen.json()["administered"] is False
        assert client.post(f"{AGENTS}/{theirs}/label", {"label": "x"}).status_code == 404
        assert client.get(f"{AGENTS}/{mine}").json()["administered"] is True
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        assert client.get(f"{AGENTS}/{theirs}").json()["administered"] is True
