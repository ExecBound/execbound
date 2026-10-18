# SPDX-License-Identifier: AGPL-3.0-only
"""The bounded Graph reader and its parsers, against a local fake directory.

Covers the first halves of SR2, SR3 and SR13: what the collector asks for, what it refuses
to follow, and what its allowlists drop before anything is retained.
"""

import httpx
import pytest

from execbound.monitoring.graph import (
    AGENTS_PATH,
    GRAPH_ORIGIN,
    EntraConfig,
    GraphError,
    Reader,
    parse_agent,
    parse_app_role_assignment,
    parse_app_roles,
    parse_blueprint,
    parse_delegated_grant,
    parse_directory_role,
    parse_inheritable,
    parse_sponsor,
    probe,
)
from execbound.resolution.models import SystemClock
from execbound_harness.fake_graph import (
    CLIENT,
    DIRECTORY,
    MICROSOFT_GRAPH,
    SECRET,
    Scenario,
    serving,
    transport,
)

BLUEPRINT_OBJECT = "bbbbbbbb-0000-4000-8000-000000000001"
BLUEPRINT_APP = "bbbbbbbb-0000-4000-8000-0000000000ff"
BELL = chr(7)


def agent_record(index: int, **overrides):
    return {
        "@odata.type": "#microsoft.graph.agentIdentity",
        "id": f"aaaaaaaa-0000-4000-8000-{index:012d}",
        "displayName": f"Synthetic agent {index}",
        "accountEnabled": True,
        "createdDateTime": "2026-09-01T10:00:00Z",
        "agentIdentityBlueprintId": BLUEPRINT_APP,
        "servicePrincipalType": "ServiceIdentity",
        "tags": [],
        **overrides,
    }


def reader_for(server, *, directory=DIRECTORY, secret=SECRET):
    client = httpx.Client(transport=transport(server), trust_env=False)
    return Reader(directory, CLIENT, secret, client)


def test_a_run_acquires_one_token_and_then_only_reads():
    scenario = Scenario(agents=[agent_record(index) for index in range(3)])
    with serving(scenario) as server:
        reader = reader_for(server)
        reader.authenticate()
        records = list(reader.walk(AGENTS_PATH, limit=10))
    assert len(records) == 3
    paths = [path for path, _, _ in server.requests]
    assert sum(1 for path in paths if path.endswith("/oauth2/v2.0/token")) == 1
    # Every other request was a read of the collection asked for, and nothing else.
    assert [path for path in paths if not path.endswith("token")] == [AGENTS_PATH]


def test_the_token_is_never_sent_anywhere_but_the_login_origin():
    scenario = Scenario(agents=[agent_record(0)])
    with serving(scenario) as server:
        reader = reader_for(server)
        reader.authenticate()
        list(reader.walk(AGENTS_PATH, limit=10))
    token_headers = [h for path, _, h in server.requests if path.endswith("token")]
    graph_headers = [h for path, _, h in server.requests if not path.endswith("token")]
    assert all("Authorization" not in headers for headers in token_headers)
    assert all(headers["Authorization"].startswith("Bearer ") for headers in graph_headers)


def test_a_token_failure_never_reaches_graph():
    with serving(Scenario(token_status=401)) as server:
        reader = reader_for(server)
        with pytest.raises(GraphError) as failure:
            reader.authenticate()
        assert failure.value.code == "AUTH_LOST"
        # A reader with no token asks for nothing rather than trying unauthenticated.
        with pytest.raises(GraphError) as second:
            list(reader.walk(AGENTS_PATH, limit=10))
        assert second.value.code == "AUTH_LOST"
    assert [path for path, _, _ in server.requests if not path.endswith("token")] == []


def test_a_resource_that_refuses_a_page_size_is_never_sent_one():
    """/directoryRoles answers 400 "This resource does not support custom page sizes", so a
    probe that sent one read it as "we could not tell" and the whole role-collection path was
    skipped in silence. Verified against a live tenant on 18 September 2026."""
    from execbound.monitoring.graph import NO_PAGE_SIZE, ROLES_PATH

    assert ROLES_PATH in NO_PAGE_SIZE
    scenario = Scenario(agents=[agent_record(0)])
    with serving(scenario) as server:
        reader = reader_for(server)
        reader.authenticate()
        probe(reader, SystemClock().now())
        list(reader.walk(ROLES_PATH, limit=10))
    for path, query, _ in server.requests:
        if path == ROLES_PATH:
            assert "$top" not in query, query
    # Every other collection still asks for a page, so the bound is not lost everywhere.
    assert any(path == AGENTS_PATH and "$top" in query for path, query, _ in server.requests)


def test_pagination_walks_every_page_and_stops_at_the_bound():
    scenario = Scenario(agents=[agent_record(index) for index in range(7)], max_top=3)
    with serving(scenario) as server:
        reader = reader_for(server)
        reader.authenticate()
        assert len(list(reader.walk(AGENTS_PATH, limit=100))) == 7
        server.requests.clear()
        # The bound is the collector's, not the platform's: it stops asking once it is met.
        assert len(list(reader.walk(AGENTS_PATH, limit=4))) == 4
    assert len([path for path, _, _ in server.requests if path == AGENTS_PATH]) == 2


def test_a_read_that_must_be_whole_is_refused_when_its_pages_run_out_first():
    """The page bound assumes full pages. Where the platform serves shorter ones, a read that
    must be whole is refused with the caller's code rather than returned short; any other read
    keeps its silent cut."""
    scenario = Scenario(agents=[agent_record(index) for index in range(7)], max_top=3)
    with serving(scenario) as server:
        reader = reader_for(server)
        reader.authenticate()
        # Fifty records is two pages of the hundred it asks for, and Graph pages three.
        assert len(list(reader.walk(AGENTS_PATH, limit=50))) == 6
        with pytest.raises(GraphError) as failure:
            list(reader.walk(AGENTS_PATH, limit=50, whole="AGENT_CAPACITY"))
        assert failure.value.code == "AGENT_CAPACITY"
        # Reaching the end within the pages, or the record bound itself, is not refused.
        server.scenario.agents = server.scenario.agents[:6]
        assert len(list(reader.walk(AGENTS_PATH, limit=50, whole="AGENT_CAPACITY"))) == 6
        server.scenario.agents = [agent_record(index) for index in range(7)]
        assert len(list(reader.walk(AGENTS_PATH, limit=4, whole="AGENT_CAPACITY"))) == 4


@pytest.mark.parametrize(
    "link",
    [
        # Another host entirely, which is the whole point of the check.
        "https://contoso.example/v1.0/servicePrincipals/microsoft.graph.agentIdentity?$top=3",
        # The pinned host, but a different read: a response must not redirect the collector
        # from the collection it asked for to one it did not.
        f"{GRAPH_ORIGIN}/v1.0/users?$top=3",
        f"http://graph.microsoft.com{AGENTS_PATH}?$top=3",
        "/v1.0/servicePrincipals/microsoft.graph.agentIdentity?$top=3",
    ],
)
def test_a_continuation_that_leaves_the_read_is_refused(link):
    scenario = Scenario(
        agents=[agent_record(index) for index in range(7)], max_top=3, next_link=link
    )
    with serving(scenario) as server:
        reader = reader_for(server)
        reader.authenticate()
        with pytest.raises(GraphError) as failure:
            list(reader.walk(AGENTS_PATH, limit=100))
        assert failure.value.code == "MALFORMED"


def test_a_forbidden_capability_leaves_the_others_available():
    scenario = Scenario(status={"agents": 403, "applications": 404})
    with serving(scenario) as server:
        reader = reader_for(server)
        reader.authenticate()
        states = probe(reader, SystemClock().now())
    assert states["agent_identities"]["state"] == "forbidden"
    assert states["applications"]["state"] == "unsupported"
    assert states["service_principals"]["state"] == "available"
    assert states["grants"]["state"] == "available"
    assert all(state["at"] for state in states.values())


def test_throttling_one_capability_decides_nothing_about_the_others():
    scenario = Scenario(status={"principals": 429}, retry_after="42")
    with serving(scenario) as server:
        reader = reader_for(server)
        reader.authenticate()
        states = probe(reader, SystemClock().now())
    # Being throttled is the platform's answer to this run, never a statement that the
    # capability is missing, and it says nothing at all about the other four.
    assert states["service_principals"]["state"] == "unknown"
    assert states["agent_identities"]["state"] == "available"
    assert states["applications"]["state"] == "available"
    assert states["directory_roles"]["state"] == "available"


def test_throttling_a_read_reports_the_delay_and_does_not_retry():
    scenario = Scenario(agents=[agent_record(0)], status={"agents": 429}, retry_after="97")
    with serving(scenario) as server:
        reader = reader_for(server)
        reader.authenticate()
        with pytest.raises(GraphError) as failure:
            list(reader.walk(AGENTS_PATH, limit=10))
        assert failure.value.code == "RATE_LIMITED"
        assert failure.value.retry_after == 97
    assert len([path for path, _, _ in server.requests if path == AGENTS_PATH]) == 1


def test_an_oversized_response_is_refused_before_it_is_parsed():
    scenario = Scenario(agents=[agent_record(index) for index in range(3)], padding=2 * 1024 * 1024)
    with serving(scenario) as server:
        reader = reader_for(server)
        reader.authenticate()
        with pytest.raises(GraphError) as failure:
            list(reader.walk(AGENTS_PATH, limit=10))
        assert failure.value.code == "OVERSIZE"


def test_an_open_type_property_is_dropped_and_counted():
    """agentIdentity admits properties the vendor has not published; none may be retained."""
    record = agent_record(
        1,
        notes="an undocumented property",
        ownerEmail="person@example.invalid",
        customSecurityAttributes={"team": "platform"},
    )
    parsed = parse_agent(record)
    assert parsed is not None
    assert parsed.dropped == 3
    kept = str(parsed)
    assert "undocumented" not in kept and "example.invalid" not in kept
    assert parsed.platform_ref == record["id"]
    assert parsed.identity_class == "agent_identity"
    assert parsed.blueprint_ref == BLUEPRINT_APP


def test_a_display_name_is_cleaned_and_bounded():
    parsed = parse_agent(agent_record(1, displayName=f"  Payroll{BELL} agent  "))
    assert parsed is not None and parsed.display_name == "Payroll agent"
    assert not parsed.display_name_truncated
    long = parse_agent(agent_record(1, displayName="n" * 200))
    assert long is not None and len(long.display_name) == 96 and long.display_name_truncated
    unnamed = parse_agent(agent_record(1, displayName=None))
    assert unnamed is not None and unnamed.display_name == "Unnamed"


def test_the_cast_collection_classifies_without_an_odata_type():
    """A live tenant on 18 September 2026 returned agent identities from
    /servicePrincipals/microsoft.graph.agentIdentity with no @odata.type field at all. The
    first design keyed on exactly that, so every agent identity in a real directory would
    have been filed as a classic service principal with its blueprint dropped."""
    record = {
        "id": "aaaaaaaa-0000-4000-8000-000000000042",
        "displayName": "Synthetic agent 42",
        "accountEnabled": True,
        "agentIdentityBlueprintId": BLUEPRINT_APP,
        "servicePrincipalType": "ServiceIdentity",
        "createdDateTime": "2026-09-18T01:20:00Z",
        "tags": [],
    }
    assert "@odata.type" not in record
    # The URL is the type assertion: every member of that collection is an agent identity.
    parsed = parse_agent(record, cast_collection=True)
    assert parsed is not None
    assert parsed.identity_class == "agent_identity"
    assert parsed.blueprint_ref == BLUEPRINT_APP

    # And the documented discriminator carries it even without the collection's provenance.
    fallback = parse_agent(record)
    assert fallback is not None and fallback.identity_class == "agent_identity"

    # A principal that is neither is still classic, whichever way it arrives.
    classic = {**record, "servicePrincipalType": "Application"}
    del classic["agentIdentityBlueprintId"]
    plain = parse_agent(classic)
    assert plain is not None and plain.identity_class == "service_principal"


def test_a_tag_is_evidence_and_never_promotes_a_service_principal_to_an_agent():
    record = agent_record(1, tags=["AgenticInstance", "power-virtual-agents-x"])
    del record["@odata.type"]
    # A classic principal as the directory returns one; the tags are the only agent-ish
    # thing about it, and tags never decide the class.
    record["servicePrincipalType"] = "Application"
    del record["agentIdentityBlueprintId"]
    parsed = parse_agent(record)
    assert parsed is not None
    assert parsed.identity_class == "service_principal"
    assert parsed.tags == ("AgenticInstance", "power-virtual-agents-x")
    # A classic principal has no blueprint, whatever a property claims.
    assert parsed.blueprint_ref is None


def test_a_sponsor_keeps_an_object_identifier_and_nothing_about_the_person():
    parsed = parse_sponsor(
        {
            "@odata.type": "#microsoft.graph.user",
            "id": "cccccccc-0000-4000-8000-000000000001",
            "displayName": "A Person",
            "mail": "person@example.invalid",
            "userPrincipalName": "person@example.invalid",
        }
    )
    assert parsed is not None
    assert parsed.kind == "user" and parsed.ref == "cccccccc-0000-4000-8000-000000000001"
    assert "example.invalid" not in str(parsed) and "Person" not in str(parsed)
    group = parse_sponsor(
        {"@odata.type": "#microsoft.graph.group", "id": "cccccccc-0000-4000-8000-000000000002"}
    )
    assert group is not None and group.kind == "group"


def test_a_directory_role_is_read_only_from_an_object_that_says_it_is_one():
    role = parse_directory_role(
        {
            "@odata.type": "#microsoft.graph.directoryRole",
            "id": "dddddddd-0000-4000-8000-000000000001",
            "roleTemplateId": "c4e39bd9-1100-46d3-8c65-fb160da0071f",
            "displayName": "Authentication Administrator",
        }
    )
    assert role == "c4e39bd9-1100-46d3-8c65-fb160da0071f"
    # A group membership is not a role, even though it arrives in the same collection.
    assert (
        parse_directory_role(
            {
                "@odata.type": "#microsoft.graph.group",
                "id": "dddddddd-0000-4000-8000-000000000002",
                "roleTemplateId": "c4e39bd9-1100-46d3-8c65-fb160da0071f",
            }
        )
        is None
    )


def test_a_blueprint_records_which_kinds_of_credential_it_holds_not_the_credentials():
    parsed = parse_blueprint(
        {
            "id": BLUEPRINT_OBJECT,
            "appId": BLUEPRINT_APP,
            "keyCredentials": [{"keyId": "k1", "displayName": "cert", "key": "BASE64=="}],
            "passwordCredentials": [{"keyId": "p1", "hint": "abc", "displayName": "secret"}],
        }
    )
    assert parsed is not None
    assert set(parsed.credential_kinds) == {"certificate", "secret"}
    rendered = str(parsed)
    assert "BASE64" not in rendered and "abc" not in rendered and "k1" not in rendered


def test_an_all_allowed_declaration_becomes_a_grant_held_on_the_blueprint():
    grants = parse_inheritable(
        {
            "resourceAppId": MICROSOFT_GRAPH,
            "inheritableScopes": {
                "@odata.type": "#microsoft.graph.allAllowedScopes",
                "kind": "allAllowed",
            },
            "inheritableRoles": {"@odata.type": "#microsoft.graph.noRoles", "kind": "none"},
        },
        BLUEPRINT_APP,
    )
    assert len(grants) == 1
    assert grants[0].grant_kind == "inherited_scopes"
    assert grants[0].inherited is True
    # The blueprint is where the permission actually sits, and where it has to be fixed.
    assert grants[0].path_ref == BLUEPRINT_APP
    assert grants[0].resource_ref == MICROSOFT_GRAPH
    # "none" declares the absence of a grant, which is not a grant.
    assert (
        parse_inheritable(
            {
                "resourceAppId": MICROSOFT_GRAPH,
                "inheritableScopes": {"kind": "none"},
                "inheritableRoles": {"kind": "none"},
            },
            BLUEPRINT_APP,
        )
        == ()
    )


def test_resource_app_roles_resolve_an_identifier_to_a_published_name():
    role_id = "3011c876-62b7-4ada-afa2-506cbbecc68c"
    resolved = parse_app_roles(
        {
            "appId": MICROSOFT_GRAPH,
            "appRoles": [
                {"id": role_id, "value": "User.EnableDisableAccount.All", "displayName": "x"},
                {"id": "not-a-guid", "value": "User.Read.All"},
                {"id": "eeeeeeee-0000-4000-8000-000000000001", "value": "not a scope name"},
                {"id": "eeeeeeee-0000-4000-8000-000000000002", "value": "User.Read.All\n"},
                {"id": "eeeeeeee-0000-4000-8000-000000000003\n", "value": "User.Read.All"},
            ],
        }
    )
    assert resolved == {role_id: "User.EnableDisableAccount.All"}


def test_a_registration_identifier_is_read_whole():
    """A final newline passes a pattern read with `re.match`, and the registration refuses it."""
    assert EntraConfig(DIRECTORY, CLIENT, "a-secret").client_id == CLIENT
    for ids in ((DIRECTORY + "\n", CLIENT), (DIRECTORY, CLIENT + "\n")):
        with pytest.raises(GraphError):
            EntraConfig(*ids, "a-secret")


def test_the_reader_resolves_a_resource_application_from_the_tenant():
    role_id = "3011c876-62b7-4ada-afa2-506cbbecc68c"
    resource_object = "ffffffff-0000-4000-8000-000000000001"
    scenario = Scenario(
        resources={
            resource_object: {
                "appId": MICROSOFT_GRAPH,
                "appRoles": [{"id": role_id, "value": "User.EnableDisableAccount.All"}],
            }
        }
    )
    with serving(scenario) as server:
        reader = reader_for(server)
        reader.authenticate()
        app_ref, roles = reader.resource_app_roles(resource_object)
    assert app_ref == MICROSOFT_GRAPH
    assert roles[role_id] == "User.EnableDisableAccount.All"


def test_a_malformed_record_yields_nothing_rather_than_a_partial_row():
    assert parse_agent({"displayName": "no identifier"}) is None
    assert parse_agent(agent_record(1, id="not-a-guid")) is None
    # Read whole: a final newline passes a pattern read with `re.match` and fails the column.
    assert parse_agent(agent_record(1, id="aaaaaaaa-0000-4000-8000-000000000001\n")) is None
    assert parse_agent(agent_record(1, tags=["tag\n"])).tags == ()
    assert parse_agent("a string") is None
    assert parse_sponsor({"id": "not-a-guid"}) is None
    assert parse_blueprint({"id": BLUEPRINT_OBJECT}) is None


def test_an_app_role_assignment_keeps_two_identifiers_and_no_display_text():
    parsed = parse_app_role_assignment(
        {
            "id": "UxOIjjUXr0WvIe4TRFgqTY4z9Wu5KxpBtlEpoTGjw-A",
            "appRoleId": "3011c876-62b7-4ada-afa2-506cbbecc68c",
            "principalId": "aaaaaaaa-0000-4000-8000-000000000001",
            "principalDisplayName": "payroll-agent",
            "resourceId": "ffffffff-0000-4000-8000-000000000001",
            "resourceDisplayName": "Microsoft Graph",
        }
    )
    assert parsed == (
        "ffffffff-0000-4000-8000-000000000001",
        "3011c876-62b7-4ada-afa2-506cbbecc68c",
    )
    assert parse_app_role_assignment({"appRoleId": "3011c876-62b7-4ada-afa2-506cbbecc68c"}) is None


def test_a_delegated_grant_keeps_only_well_formed_scope_names():
    parsed = parse_delegated_grant(
        {
            "clientId": "aaaaaaaa-0000-4000-8000-000000000001",
            "consentType": "AllPrincipals",
            "principalId": None,
            "resourceId": "ffffffff-0000-4000-8000-000000000001",
            "scope": "User.ReadWrite.All  not a scope User-PasswordProfile.ReadWrite.All",
        }
    )
    assert parsed is not None
    resource, names = parsed
    assert resource == "ffffffff-0000-4000-8000-000000000001"
    assert names == ("User.ReadWrite.All", "User-PasswordProfile.ReadWrite.All")
    assert parse_delegated_grant({"resourceId": "ffffffff-0000-4000-8000-000000000001"}) is None
