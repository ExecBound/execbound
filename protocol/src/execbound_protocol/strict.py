# SPDX-License-Identifier: Apache-2.0
"""The strict model every protocol message is, and the bounded JSON parsing they share."""

from typing import Annotated, NoReturn

from pydantic import BaseModel, ConfigDict, Field

Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Version = Annotated[str, Field(min_length=1, max_length=80)]


class StrictModel(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True, hide_input_in_errors=True)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def _reject_number(value: str) -> NoReturn:
    raise ValueError("Only integer JSON numbers are supported")
