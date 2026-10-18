# SPDX-License-Identifier: AGPL-3.0-only
"""The assistant's read tools: the person's authority, explicit projections, closed schemas,
untrusted envelopes and the secret check, against the real store."""

from uuid import uuid4

import pytest
from policy_fixtures import activated_ruleset_bundle
from sqlalchemy import text
from test_execution import registry as registry
from test_execution import targets
from test_execution import world as world
from test_human_surface import human_config as human_config
from test_human_surface import pending
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

from execbound.assistant.tools import SPECS, ToolContext, ToolError, run_tool, untrusted
from execbound.surfaces.sessions import issue_session, load_session

pytestmark = pytest.mark.integration


def session_of(db, world, identity):
    grant = issue_session(db, identity, clock=world["clock"])
    return load_session(db, grant.token, clock=world["clock"])


def context(db, runtime, world, identity):
    return ToolContext(runtime=runtime, session=session_of(db, world, identity))


def test_every_tool_has_a_closed_schema_and_refuses_what_it_does_not_admit(db, runtime, world):
    admin = context(db, runtime, world, world["admin"])
    names = {spec.name for spec in SPECS}
    assert names == {
        "overview",
        "list_executions",
        "get_execution",
        "get_approval",
        "get_policy",
        "get_limits",
        "get_agent",
        "list_findings",
        "explain_action",
        "help",
        "get_contract",
    }
    for spec in SPECS:
        wire = spec.wire()
        assert wire["strict"] is True and wire["input_schema"]["additionalProperties"] is False
    with pytest.raises(ToolError) as unknown:
        run_tool(admin, "search_everything", {})
    assert unknown.value.code == "UNKNOWN_TOOL"
    for name, arguments in (
        ("overview", {"extra": 1}),
        ("get_execution", {}),
        ("get_execution", {"execution_id": "not-a-uuid"}),
        ("get_execution", {"execution_id": 42}),
        ("list_executions", {"limit": 51}),
        ("list_executions", {"since_hours": 0}),
        ("list_findings", {"state": "everything"}),
        ("explain_action", {"action": ""}),
    ):
        with pytest.raises(ToolError) as refused:
            run_tool(admin, name, arguments)
        assert refused.value.code == "INVALID_ARGUMENTS", (name, arguments)


def test_the_overview_projects_what_a_person_can_still_decide_and_what_lapsed(db, runtime, world):
    """`pending` is what a person can still decide, and `lapsed` what ran out of time before a
    decision and awaits the recovery run (#678): a lapsed approval is in the second only."""
    from datetime import timedelta

    from test_approval_deadline import deadline, long_facts
    from test_execution import request

    from execbound.execution import admit

    long_facts(db, world)
    deadline(db, world, 600)
    held = admit(db, world["identity"], request(world), world["clock"]).view
    assert held.state == "PENDING_APPROVAL"
    admin = context(db, runtime, world, world["admin"])
    before = run_tool(admin, "overview", {})
    assert before.data["pending"] == 1 and before.data["lapsed"] == 0
    world["clock"].value += timedelta(seconds=601)
    after = run_tool(context(db, runtime, world, world["admin"]), "overview", {})
    assert after.data["pending"] == 0 and after.data["lapsed"] == 1


def test_the_overview_the_policy_and_an_action_read_through_the_page_functions(db, runtime, world):
    admin = context(db, runtime, world, world["admin"])
    overview = run_tool(admin, "overview", {})
    assert overview.data["bundle_id"] == str(world["bundle"].bundle_id)
    assert overview.data["mode"] == "ENFORCE" and overview.data["pending"] == 0
    assert str(world["bundle"].bundle_id) in overview.ids
    assert overview.step == "Read the overview"
    policy = run_tool(admin, "get_policy", {})
    assert policy.data["written_as"] == "policy text"
    assert "permit(principal" in policy.data["authorization_policies"]["untrusted"]
    assert {rule["rule_id"] for rule in policy.data["limits"]} == {
        rule.rule_id for rule in world["bundle"].limits
    }
    activated_ruleset_bundle(db, world)
    as_rules = run_tool(admin, "get_policy", {})
    assert as_rules.data["written_as"] == "rules"
    sentences = {rule["id"]: rule["sentence"] for rule in as_rules.data["rules"]}
    assert sentences["isolate-never-domain-controller"] == (
        "Deny endpoint.isolate when role is domain_controller."
    )
    assert "isolate-never-domain-controller" in as_rules.ids
    action = run_tool(admin, "explain_action", {"action": "endpoint.isolate"})
    assert action.data["found"] and action.data["reversed_by"] == "endpoint.lift_isolation"
    names = {argument["name"] for argument in action.data["arguments"]}
    assert names == {a.name for a in runtime.catalog.actions.action("endpoint.isolate").arguments}
    assert any(b["provider"] == "mock_crowdstrike" for b in action.data["bindings"])
    unknown = run_tool(admin, "explain_action", {"action": "endpoint.explode"})
    assert unknown.data == {"found": False, "reason": "UNKNOWN_ACTION"}

    # The one tool that reads nothing of the tenant's: the same answer for everyone.
    text_answer = run_tool(admin, "help", {"topic": "approvals"})
    assert text_answer.data["found"] and "consumed once" in text_answer.data["text"]
    assert text_answer.ids == () and text_answer.step == "Read the help text on approvals"
    with pytest.raises(ToolError) as bad_topic:
        run_tool(admin, "help", {"topic": "everything"})
    assert bad_topic.value.code == "INVALID_ARGUMENTS"


def test_the_policy_and_its_contract_name_the_action_a_custom_ref_serves(
    db, runtime, world, admin_engine
):
    """A bundle mapping `endpoint.isolate` under the ref `alternate.isolate` serves the action."""
    from execbound.policy.models import MappingRef
    from execbound.policy.rulesets import ruleset_bundle
    from execbound.policy.store import activate_bundle, create_bundle, validate_bundle
    from execbound_harness.demo import ENDPOINT_RULESET

    tenant = world["identity"].tenant_id
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.operation_mappings "
                "SELECT tenant_id,'alternate.isolate',account_id,provider,resource_type,action,"
                "provider_operation,mapping_version,schema_version,context_contract_version,active "
                "FROM execbound.operation_mappings "
                "WHERE tenant_id=:t AND operation_ref='endpoint.isolate'"
            ),
            {"t": tenant},
        )
    reference = MappingRef(
        **world["bundle"].mappings[0].model_dump(exclude={"operation_ref"}),
        operation_ref="alternate.isolate",
        action="endpoint.isolate",
    )
    content = ruleset_bundle(
        ENDPOINT_RULESET, tenant_id=tenant, bundle_id=uuid4(), mappings=(reference,)
    )
    create_bundle(db, world["admin"], content, world["clock"])
    validate_bundle(db, world["admin"], content.bundle_id, world["clock"])
    activate_bundle(db, world["admin"], content.bundle_id, world["clock"])
    admin = context(db, runtime, world, world["admin"])
    assert run_tool(admin, "get_policy", {}).data["actions"] == ["endpoint.isolate"]
    served = run_tool(admin, "get_contract", {"action": "endpoint.isolate"}).data
    assert [item["action"] for item in served["actions"]] == ["endpoint.isolate"]
    assert served["actions"][0]["fields"]


def test_the_policy_names_the_action_a_hand_written_ref_serves_without_naming_it(
    db, runtime, world, admin_engine
):
    """A bundle written by hand may map `endpoint.isolate` under `alternate.isolate` and leave
    `action` out. The store reads such a bundle by its mapping rows (`policy/store._components`)
    and admission dispatches the row's action, so the policy's actions are the rows' too, never
    the ref's own name, as the Agents page reads them (`agents_pages.limit_rows`)."""
    from execbound.policy.models import BundleContent, MappingRef
    from execbound.policy.store import activate_bundle, create_bundle, validate_bundle

    tenant = world["identity"].tenant_id
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.operation_mappings "
                "SELECT tenant_id,'alternate.isolate',account_id,provider,resource_type,action,"
                "provider_operation,mapping_version,schema_version,context_contract_version,active "
                "FROM execbound.operation_mappings "
                "WHERE tenant_id=:t AND operation_ref='endpoint.isolate'"
            ),
            {"t": tenant},
        )
    reference = MappingRef(
        **world["bundle"].mappings[0].model_dump(exclude={"operation_ref"}),
        operation_ref="alternate.isolate",
    )
    # The ref names no action, so the bundle alone would say it serves `alternate.isolate`.
    assert reference.action is None and reference.action_name == "alternate.isolate"
    content = BundleContent(
        tenant_id=tenant,
        bundle_id=uuid4(),
        cedar_schema=world["bundle"].cedar_schema,
        authorization_policies=world["bundle"].authorization_policies,
        approval_policies=world["bundle"].approval_policies,
        mappings=(reference,),
        limits=(),
    )
    assert content.ruleset is None
    create_bundle(db, world["admin"], content, world["clock"])
    validate_bundle(db, world["admin"], content.bundle_id, world["clock"])
    activate_bundle(db, world["admin"], content.bundle_id, world["clock"])
    admin = context(db, runtime, world, world["admin"])
    policy = run_tool(admin, "get_policy", {})
    assert policy.data["bundle_id"] == str(content.bundle_id)
    assert policy.data["written_as"] == "policy text"
    assert policy.data["actions"] == ["endpoint.isolate"]


def test_an_approver_reads_a_scoped_request_whole_and_nothing_outside_the_scope(
    db, runtime, world, admin_engine, live_provider
):
    from demo_world import provision_mock

    provision_mock(live_provider, admin_engine, world)
    waiting = pending(runtime, world)
    assert waiting.state == "PENDING_APPROVAL"
    # A second target the approver is not scoped to, executed without a person.
    outside = targets(admin_engine, world, 2)[1]
    executed = runtime.execute(world["identity"], outside.model_dump_json().encode())
    # The helper scopes the approver to every target it makes; withdraw this one.
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.approval_scopes s SET active = false "
                "FROM execbound.resource_identities ri "
                "WHERE ri.tenant_id = s.tenant_id "
                "AND ri.canonical_target_id = s.canonical_target_id "
                "AND ri.resource_id = CAST(:r AS uuid) AND s.approver_id = :p"
            ),
            {"r": outside.target.value, "p": world["human"].principal_id},
        )
    approver = context(db, runtime, world, world["human"])
    listed = run_tool(approver, "list_executions", {})
    ids = {row["execution_id"] for row in listed.data["executions"]}
    assert str(waiting.execution_id) in ids and str(executed.execution_id) not in ids
    assert listed.step == "Read 1 executions"
    detail = run_tool(approver, "get_execution", {"execution_id": str(waiting.execution_id)})
    assert detail.data["found"] and detail.data["action"] == "endpoint.isolate"
    assert detail.data["target"] == {"kind": "hostname", "value": untrusted("ws01.example")}
    facts = {fact["name"]: fact["value"] for fact in detail.data["facts"]}
    assert facts["role"] == "workstation" and facts["is_production"] is True
    assert detail.data["approval"]["state"] == "PENDING"
    assert detail.data["approval"]["deadline"] is not None
    assert any(event["effect"] == "REQUIRE_APPROVAL" for event in detail.data["events"])
    assert str(waiting.approval_id) in detail.ids
    approval = run_tool(approver, "get_approval", {"approval_id": str(waiting.approval_id)})
    assert approval.data["found"] and approval.data["required_approvers"] == 1
    assert approval.data["obligation_ids"] and approval.data["decisions"] == []
    assert approval.data["execution"]["execution_id"] == str(waiting.execution_id)
    # Outside the scope the answer is a refusal, the same one the page gives.
    hidden = run_tool(approver, "get_execution", {"execution_id": str(executed.execution_id)})
    assert hidden.data == {"found": False, "reason": "NOT_FOUND"} and hidden.ids == ()
    absent = run_tool(approver, "get_approval", {"approval_id": str(uuid4())})
    assert absent.data == {"found": False, "reason": "NOT_FOUND"}
    # The administrator sees both.
    admin = context(db, runtime, world, world["admin"])
    both = run_tool(admin, "list_executions", {"limit": 10})
    assert {row["execution_id"] for row in both.data["executions"]} >= {
        str(waiting.execution_id),
        str(executed.execution_id),
    }


def test_agent_reads_are_the_administrators_and_every_string_is_enveloped(
    db, runtime, world, admin_engine
):
    principal = world["identity"].principal_id
    approver = context(db, runtime, world, world["human"])
    refused = run_tool(approver, "get_agent", {"agent_principal_id": str(principal)})
    assert refused.data["found"] is False and refused.ids == ()
    admin = context(db, runtime, world, world["admin"])
    agent = run_tool(admin, "get_agent", {"agent_principal_id": str(principal)})
    assert agent.data["found"] and agent.data["agent_principal_id"] == str(principal)
    assert agent.data["label"] is None or "untrusted" in agent.data["label"]
    assert {row["action"] for row in agent.data["reach"]} == {"endpoint.isolate"}
    assert "credentials" not in agent.data and "token" not in str(agent.data).lower()
    limits = run_tool(admin, "get_limits", {"agent_principal_id": str(principal)})
    assert limits.data["found"] and all("rule_id" in row for row in limits.data["limits"])
    findings = run_tool(admin, "list_findings", {})
    assert findings.data == {"findings": [], "count": 0} and findings.step == "Read 0 findings"


def test_a_secret_shaped_string_in_tenant_data_ends_the_turn_before_it_leaves(
    db, runtime, world, admin_engine
):
    principal = world["identity"].principal_id
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.principals SET label = :l WHERE principal_id = :p"),
            {"l": "Bearer " + "A1B2C3D4E5F6G7H8", "p": principal},
        )
    admin = context(db, runtime, world, world["admin"])
    with pytest.raises(ToolError) as leaked:
        run_tool(admin, "get_agent", {"agent_principal_id": str(principal)})
    assert leaked.value.code == "REFUSED_SECRET"
