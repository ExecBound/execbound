# SPDX-License-Identifier: Apache-2.0
"""The bounded scalar arguments an action request carries and a provider command repeats."""

from typing import Annotated, Self

from pydantic import ConfigDict, Field, RootModel, model_validator

from execbound_protocol.domains import LONG_MAX, LONG_MIN, MAX_ARGUMENTS

ArgumentName = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,62}$")]
ArgumentValue = str | int | bool


class Arguments(RootModel[dict[ArgumentName, ArgumentValue]]):
    """Bounded scalar options; the resolved action's catalog spec decides which are valid."""

    model_config = ConfigDict(
        strict=True, frozen=True, hide_input_in_errors=True, revalidate_instances="always"
    )
    root: dict[ArgumentName, ArgumentValue] = Field(default_factory=dict)

    @model_validator(mode="after")
    def bounded_scalars(self) -> Self:
        if len(self.root) > MAX_ARGUMENTS:
            raise ValueError("Too many arguments")
        for value in self.root.values():
            if type(value) is str:
                if not 1 <= len(value) <= 254:
                    raise ValueError("Invalid argument string")
            elif type(value) is int:
                if not LONG_MIN <= value <= LONG_MAX:
                    raise ValueError("Invalid argument integer")
            elif type(value) is not bool:
                raise ValueError("Invalid argument value")
        # A validated instance owns its mapping, so a caller holding the parsed request cannot
        # reach into a frozen intent and change what was hashed.
        object.__setattr__(self, "root", dict(self.root))
        return self

    def __hash__(self) -> int:
        # Supports the ActionRequest hashability check; frozen=True alone cannot hash a dict
        # root. Equality and hashing never decide authority: True == 1 in Python, so
        # Arguments({"a": True}) == Arguments({"a": 1}) while their canonical JSON, and
        # therefore every kernel hash, differs.
        return hash(tuple(sorted(self.root.items())))
