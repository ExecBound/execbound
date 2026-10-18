# SPDX-License-Identifier: AGPL-3.0-only
"""The packaged help texts, held to the documents they summarise.

The image carries no `docs/`, so these texts are what an assistant can say about how ExecBound
works. A text that drifted into describing something the product does not do would be worse
than no text at all, so each one names the document that states its facts and the phrases that
must appear in both. The pattern is `docs/INTEGRATIONS.md`'s: a claim is held to its source
rather than to a reviewer's memory.
"""

from pathlib import Path

import pytest

from execbound.assistant.help import TOPICS, text_of

ROOT = Path(__file__).resolve().parents[1]

# topic -> (the document that states these facts, the phrases both must carry)
#
# "scenarios" is not here: its source moved to the hosted plugin (#496), and a core test does
# not read hosted source. `SCENARIOS_TOPIC` keeps the completeness check below accounting for
# it without reading anything.
SCENARIOS_TOPIC = "scenarios"
SOURCES = {
    "states": (
        "docs/API_REFERENCE.md",
        ("PENDING_APPROVAL", "FAILED_NOT_EXECUTED", "FAILED_EFFECT_UNKNOWN", "OBSERVED"),
    ),
    "obligations": ("docs/POLICY.md", ("obligation", "approval set", "quorum")),
    "approvals": ("docs/EXECUTION.md", ("consumed", "expir", "approver")),
    "budgets": ("docs/POLICY.md", ("window", "selector", "approval")),
    "connecting": ("docs/API_REFERENCE.md", ("/v1/execute", "MCP")),
}


def test_every_topic_has_a_source_and_every_text_is_one_bounded_paragraph():
    assert set(SOURCES) | {SCENARIOS_TOPIC} == set(TOPICS), (
        "a topic without a source, or a source without a topic"
    )
    for topic in TOPICS:
        text = text_of(topic)
        assert "\n" not in text and text == text.strip()
        assert 200 <= len(text) <= 1200, (topic, len(text))
        # Facts about the product, never advice about a decision.
        lowered = text.lower()
        assert "you should" not in lowered and "i recommend" not in lowered
        assert "recommend" not in lowered or topic == "obligations"


@pytest.mark.docs
@pytest.mark.parametrize("topic", sorted(SOURCES))
def test_each_text_says_what_its_document_says(topic):
    """The phrases that carry the claim appear in the text and in the document it summarises,
    so a text cannot drift from the product without failing here."""
    source, phrases = SOURCES[topic]
    document = (ROOT / source).read_text(encoding="utf-8").lower()
    text = text_of(topic).lower()
    for phrase in phrases:
        assert phrase.lower() in text, (topic, phrase, "missing from the help text")
        assert phrase.lower() in document, (topic, phrase, f"missing from {source}")


def test_an_unknown_topic_is_a_key_error_the_tool_turns_into_a_refusal():
    with pytest.raises(KeyError):
        text_of("everything")
