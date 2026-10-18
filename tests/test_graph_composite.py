# SPDX-License-Identifier: AGPL-3.0-only
"""The frozen composite for a Graph user: the recipe, its stability and every refusal."""

import pytest
from pydantic import TypeAdapter, ValidationError

from execbound.provider.composite import (
    GRAPH_USER_FIELDS,
    GRAPH_USER_V1,
    CompositeDrift,
    graph_user_composite,
)
from execbound.resolution.models import Version

USER = {
    "id": "6f1b0c2e-6f40-4a2c-9a3f-2f6c0b1d7e55",
    "accountEnabled": True,
    "userPrincipalName": "agent@contoso.onmicrosoft.com",
    "onPremisesSyncEnabled": None,
}


def test_the_composite_fits_the_frozen_plans_existing_version_field():
    """It has to, or it cannot be carried without adding a field to ResolvedRequest.

    plan_hash hashes that whole model, so a new field would move every frozen plan hash in
    history and break the endpoint and identity contract fixtures.
    """
    frozen = graph_user_composite(USER)
    assert TypeAdapter(Version).validate_python(frozen) == frozen
    assert len(frozen) <= 80
    assert frozen.startswith(GRAPH_USER_V1 + ":")


def test_the_same_reading_hashes_the_same_however_it_arrives():
    reordered = {name: USER[name] for name in reversed(list(USER))}
    assert graph_user_composite(reordered) == graph_user_composite(USER)


@pytest.mark.parametrize("field", sorted(GRAPH_USER_FIELDS))
def test_a_change_in_any_covered_field_changes_the_composite(field):
    """One regression per field: a field that does not move the hash is not covered by it."""
    moved = {
        "id": "00000000-0000-4000-8000-000000000000",
        "accountEnabled": False,
        "userPrincipalName": "someone-else@contoso.onmicrosoft.com",
        "onPremisesSyncEnabled": True,
    }[field]
    assert graph_user_composite({**USER, field: moved}) != graph_user_composite(USER)


def test_null_and_false_are_different_answers_for_the_synced_flag():
    """Graph answers null for a cloud-only user and true for a synced one.

    Collapsing null to false would let a synced user, whose disable the on-premises
    directory reverts, hash the same as a cloud-only one whose disable sticks.
    """
    assert graph_user_composite({**USER, "onPremisesSyncEnabled": None}) != graph_user_composite(
        {**USER, "onPremisesSyncEnabled": False}
    )


@pytest.mark.parametrize(
    "reading,reason",
    [
        ({**USER, "jobTitle": "Agent"}, "unknown-field"),
        ({name: value for name, value in USER.items() if name != "id"}, "missing-field"),
        ({**USER, "accountEnabled": 1}, "int-where-a-bool-was"),
        ({**USER, "accountEnabled": "true"}, "string-where-a-bool-was"),
        ({**USER, "onPremisesSyncEnabled": "no"}, "string-where-a-nullable-bool-was"),
        ({**USER, "id": ""}, "empty-id"),
        ({**USER, "userPrincipalName": ""}, "empty-upn"),
    ],
    ids=[
        "unknown-field",
        "missing-field",
        "int-where-a-bool-was",
        "string-where-a-bool-was",
        "string-where-a-nullable-bool-was",
        "empty-id",
        "empty-upn",
    ],
)
def test_a_reading_this_recipe_was_not_written_against_is_refused(reading, reason):
    """Graph resources are open types, so an allowlist is load-bearing, not decorative."""
    with pytest.raises(CompositeDrift):
        graph_user_composite(reading)


def test_a_bool_is_not_accepted_where_an_int_would_pass_isinstance():
    """In Python True is an int. A vendor answering 1 where it answered true has drifted."""
    with pytest.raises(CompositeDrift):
        graph_user_composite({**USER, "accountEnabled": 1})


def test_the_recipe_name_is_inside_the_hash_not_only_in_front_of_it():
    """Changing which fields are covered must change every hash the recipe produces.

    Otherwise an old frozen plan would compare equal to a new reading that checked
    something different, which is the one thing a frozen precondition must never do.
    """
    frozen = graph_user_composite(USER)
    digest = frozen.split(":", 1)[1]
    import hashlib

    from execbound.audit import canonical_json

    without_recipe = hashlib.sha256(canonical_json(dict(USER)).encode()).hexdigest()
    assert digest != without_recipe


def test_a_non_object_reading_is_refused():
    for reading in ([], "user", 7, None):
        with pytest.raises((CompositeDrift, ValidationError, TypeError)):
            graph_user_composite(reading)
