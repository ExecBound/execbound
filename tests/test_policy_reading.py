# SPDX-License-Identifier: AGPL-3.0-only
"""Human readings preserve the parsed policy, including unsupported conditions."""

from execbound.policy.reading import document_reading
from execbound_harness.demo import APPROVAL, AUTHORIZATION


def test_demo_documents_expose_every_policy_with_scope_and_boolean_grouping():
    reading = document_reading(AUTHORIZATION, APPROVAL)
    assert reading["complete"] is True
    assert reading["authorization_policies"] == AUTHORIZATION
    assert reading["approval_policies"] == APPROVAL
    assert len(reading["rules"]) == 3
    permit, deny, review = reading["rules"]
    assert permit["effect"] == "Allow"
    assert "Isolate endpoint (endpoint.isolate)" in permit["description"]
    assert "agent.tenant equals target.tenant" in permit["description"]
    assert 'target.role equals "workstation"' in permit["description"]
    assert (
        '((target.role equals "domain_controller") OR (target.criticality equals 4))'
        in deny["description"]
    )
    assert review["effect"] == "Require approval"
    assert "target.is production" in review["description"]


def test_unless_and_scoped_principals_are_never_dropped():
    source = (
        'permit(principal == ExecBound::Agent::"a", action, resource) '
        "unless { resource.criticality >= 3 };"
    )
    result = document_reading(source, "")["rules"][0]
    assert 'agent equals ExecBound::Agent::"a"' in result["description"]
    assert "unless (target.criticality is at least 3)" in result["description"]


def test_unsupported_expression_keeps_the_exact_document_and_no_partial_summary():
    source = 'forbid(principal, action, resource) when { resource.tags.contains("protected") };'
    reading = document_reading(source, "")
    assert reading["complete"] is False
    assert reading["rules"][0]["effect"] == "Deny"
    assert reading["rules"][0]["description"] is None
    assert reading["authorization_policies"] == source


def test_invalid_or_template_documents_do_not_get_an_optimistic_reading():
    for source in ("invalid document", "permit(principal == ?principal, action, resource);"):
        reading = document_reading(source, "")
        assert reading["complete"] is False
        assert reading["rules"] == []
        assert reading["authorization_policies"] == source


def test_values_are_quoted_without_interpreting_their_words_as_policy():
    source = 'permit(principal, action, resource) when { resource.role == "x OR allow all" };'
    assert '"x OR allow all"' in document_reading(source, "")["rules"][0]["description"]
