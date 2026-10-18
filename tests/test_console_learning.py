# SPDX-License-Identifier: AGPL-3.0-only
"""The in-console first example really evaluates Cedar without executing anything."""

import pytest
from pydantic import ValidationError

from execbound.surfaces.console_api.learning import LearningRequest, example


@pytest.mark.parametrize(
    "scenario,effect",
    [("workstation", "ALLOW"), ("domain_controller", "DENY"), ("production", "REQUIRE_APPROVAL")],
)
def test_learning_examples_use_fixed_synthetic_inputs(scenario, effect):
    result = example(scenario)
    assert result.decision == effect
    assert result.executed is False
    assert "not your workspace policy" in result.scope


def test_learning_never_accepts_a_destination_or_real_target():
    with pytest.raises(ValidationError):
        LearningRequest(scenario="workstation", target="real-host")
    with pytest.raises(ValidationError):
        LearningRequest(scenario="real-host")
