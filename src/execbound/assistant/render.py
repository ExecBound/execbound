# SPDX-License-Identifier: AGPL-3.0-only
"""What an answer may be, and the two refusals the renderer makes.

The answer is structured output: paragraphs of plain text, each with the ids it rests on,
and a `cannot_answer` flag. The server keeps paragraphs as text and the console renders
them as text, so there is nothing here to sanitise; what there is to do is decide which ids
may become links (only ones a tool returned in the same turn) and refuse a recommendation
in an approval context, which the schema cannot express and the instructions forbid.
"""

import re
import unicodedata
from collections.abc import Collection
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

MAX_PARAGRAPHS = 12
MAX_PARAGRAPH_CHARS = 2_000
MAX_IDS = 16
MAX_ID_CHARS = 80

ANSWER_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "paragraphs": {
            "type": "array",
            "maxItems": MAX_PARAGRAPHS,
            "items": {
                "type": "object",
                "properties": {
                    "text": {"type": "string", "maxLength": MAX_PARAGRAPH_CHARS},
                    "ids": {
                        "type": "array",
                        "maxItems": MAX_IDS,
                        "items": {"type": "string", "maxLength": MAX_ID_CHARS},
                    },
                },
                "required": ["text", "ids"],
                "additionalProperties": False,
            },
        },
        "cannot_answer": {"type": "boolean"},
    },
    "required": ["paragraphs", "cannot_answer"],
    "additionalProperties": False,
}

# Fixed, so a reviewer can read the whole list. Matched case-insensitively on the answer's
# text after whitespace is collapsed; each is a way of telling a person what to decide.
RECOMMENDATION_PHRASES = (
    "you should approve",
    "you should deny",
    "you should refuse",
    "you should reject",
    "safe to approve",
    "i recommend",
    "i would approve",
    "i would deny",
    "i would refuse",
    "should be approved",
    "should be denied",
    "should be refused",
    "should be rejected",
    "recommend approving",
    "recommend denying",
    "recommend refusing",
    "approve this",
    "deny this",
    "refuse this",
)

_SPACES = re.compile(r"\s+")


class RenderError(ValueError):
    """`INVALID_ANSWER` for a shape the schema does not allow, `RECOMMENDATION` for the
    phrase list in an approval context."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class _Paragraph(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    text: str = Field(max_length=MAX_PARAGRAPH_CHARS)
    ids: list[str] = Field(max_length=MAX_IDS)


class _Answer(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    paragraphs: list[_Paragraph] = Field(max_length=MAX_PARAGRAPHS)
    cannot_answer: bool


@dataclass(frozen=True)
class Paragraph:
    text: str
    ids: tuple[str, ...]


@dataclass(frozen=True)
class Answer:
    paragraphs: tuple[Paragraph, ...]
    cannot_answer: bool


def _plain(text: str) -> str:
    """Control characters gone, whitespace collapsed; the text is otherwise the model's."""
    cleaned = "".join(ch for ch in text if ch in "\n\t" or unicodedata.category(ch)[0] != "C")
    return _SPACES.sub(" ", cleaned).strip()


def recommends(text: str) -> bool:
    lowered = _SPACES.sub(" ", text).lower()
    return any(phrase in lowered for phrase in RECOMMENDATION_PHRASES)


def parse_answer(raw: str, seen_ids: Collection[str], *, approval_context: bool) -> Answer:
    """The model's JSON as an `Answer`, with only this turn's ids kept as citations.

    An id the model wrote that no tool returned stays in the text as text and is dropped
    from the paragraph's `ids`, so the console can never link it. In an approval context a
    paragraph carrying a recommendation phrase fails the whole answer.
    """
    try:
        parsed = _Answer.model_validate_json(raw)
    except ValidationError:
        raise RenderError("INVALID_ANSWER") from None
    seen = {str(value) for value in seen_ids}
    paragraphs: list[Paragraph] = []
    for item in parsed.paragraphs:
        text = _plain(item.text)
        if not text:
            continue
        if approval_context and recommends(text):
            raise RenderError("RECOMMENDATION")
        cited = tuple(dict.fromkeys(value for value in item.ids if value in seen))
        paragraphs.append(Paragraph(text, cited))
    if not paragraphs and not parsed.cannot_answer:
        raise RenderError("INVALID_ANSWER")
    return Answer(tuple(paragraphs), parsed.cannot_answer)
