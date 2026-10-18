# SPDX-License-Identifier: Apache-2.0
"""Canonical JSON: the one serialization every hash and signature of the protocol is over.

Sorted keys, no whitespace, UTF-8 rather than escapes, and no number that is not an integer.
A value it does not admit is refused rather than coerced, so two parties that serialize the
same message always agree on its bytes.
"""

import json
from typing import Any


def canonical_json(value: Any) -> str:
    def validate(item: Any) -> None:
        if item is None or type(item) in (str, int, bool):
            return
        if type(item) is list:
            for child in item:
                validate(child)
            return
        if type(item) is dict and all(type(key) is str for key in item):
            for child in item.values():
                validate(child)
            return
        raise ValueError(
            "Audit JSON accepts only strings, integers, booleans, null, lists and objects"
        )

    validate(value)
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )
