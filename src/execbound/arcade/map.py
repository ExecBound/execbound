# SPDX-License-Identifier: AGPL-3.0-only
"""The operator's declaration of which Arcade tools are governed, and what each becomes.

See docs/ARCADE.md, The tool map. A hook names the tool it is about; the operator's
declaration says what that tool may reach. The exact toolkit, name and version pick which
declaration applies, and a tool matching neither a governed declaration nor an ungoverned
toolkit is refused, so passing requires someone to have written it down. What a declaration
produces is the wire fields ``ActionRequest`` already defines, rather than anything of its own.

The rules below are refusals rather than inferences. Reported tool metadata may only
refuse: where a declaration carries ``expect``, a report contradicting it denies, and
``_consistent`` is the one place here that reads it. It selects no declaration, no action,
no target and no incident, and it moves no tool between governed and ungoverned.
"""

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Annotated, Literal, Self

from pydantic import Field, ValidationError, model_validator

from execbound.requests import (
    ArgumentName,
    Arguments,
    ClaimedContext,
    ResourceSelector,
    StrictModel,
)

# Arcade's own tool identity. A version list is explicit and holds no wildcard, because a
# vendor can change what a tool does across versions and a wildcard would carry the
# operator's decision forward into a tool they never saw.
ToolkitName = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")]
ToolName = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")]
ToolVersion = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.+-]{0,31}$")]
InputKey = Annotated[str, Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")]
# `ActionRequest.operation_ref`'s own constraint, written out here as this project writes
# it in each module that carries it. A declaration naming a reference outside it is one no
# request this deployment parses could carry, so it is refused when the file is read rather
# than denied at every hook afterwards.
OperationRef = Annotated[
    str, Field(min_length=1, max_length=80, pattern=r"^[a-z][a-z0-9_.-]{0,79}$")
]
# The reported facts an `expect` declaration weighs. Arcade nests them under `behavior` in
# a tool's metadata, beside `behavior.operations`, which this holds no expectation about.
BehaviorFact = Literal["read_only", "destructive", "idempotent", "open_world"]


class ToolMapError(ValueError):
    """A refusal carrying a stable code and nothing the caller sent."""


class _ToolTarget(StrictModel):
    """One declared input key, extracted by name.

    There is no expression language, no path syntax and no fallback, because a second place
    that can choose a target is a second place that can decide authority. The kernel is
    what refuses an identity resource named by hostname.
    """

    kind: Literal["canonical", "hostname", "provider_id"]
    input: InputKey


class _ToolIncident(StrictModel):
    """One declared input key carrying the incident the agent says it is acting under.

    This is an extraction, in the shape `_ToolTarget` already has, and it is deliberately
    not a read of the platform's reported `metadata`: `metadata` is caller-supplied input
    that may only refuse, and an incident selected from it would be a fact the platform
    asserts. What the agent puts in a declared input is a **claim**, and the kernel is what
    checks it — `resolution.registry.incident` reads the incident row under the mapping's
    own tenant, account, provider and resource type and requires it to be an incident of
    the resolved target, so a claim naming another tenant's incident, another account's,
    or one attached to another resource resolves nothing and the request is refused.
    """

    input: InputKey


class ArcadeTool(StrictModel):
    """One governed tool: its identity, the operation it reaches and the keys it admits."""

    toolkit: ToolkitName
    name: ToolName
    versions: tuple[ToolVersion, ...] = Field(min_length=1, max_length=32)
    operation_ref: OperationRef
    target: _ToolTarget
    incident: _ToolIncident | None = None
    inputs: tuple[InputKey, ...] = Field(min_length=1, max_length=64)
    arguments: dict[InputKey, ArgumentName] = Field(default_factory=dict, max_length=16)
    expect: dict[BehaviorFact, bool] = Field(default_factory=dict)

    @model_validator(mode="after")
    def declared_once(self) -> Self:
        """Every key this declaration uses is one of its own inputs, named once.

        A target or an argument drawn from a key the declaration does not admit could never
        be filled, because `inputs` is an allowlist and everything else is refused; and two
        inputs mapped to one argument would make which of them is sent depend on the order
        the file happens to list them in.
        """
        if len(set(self.versions)) != len(self.versions):
            raise ValueError("Duplicate tool version")
        if len(set(self.inputs)) != len(self.inputs):
            raise ValueError("Duplicate input key")
        if self.target.input not in self.inputs:
            raise ValueError("The target key is not a declared input")
        if self.incident is not None and self.incident.input not in self.inputs:
            raise ValueError("The incident key is not a declared input")
        if not set(self.arguments) <= set(self.inputs):
            raise ValueError("An argument is mapped from an undeclared input")
        if len(set(self.arguments.values())) != len(self.arguments):
            raise ValueError("Two inputs are mapped to one argument")
        return self


class ArcadeBlock(StrictModel):
    """The `arcade` block of the private configuration file.

    `deadline_seconds` is required with no default: a default would be a number the
    deployment inherits silently, chosen against a measurement of some path other than the
    one it has to survive, so a block omitting it is refused when the file is read, with the
    same opaque answer the loader gives any file it refuses. The upper bound it carries here
    is a connector timeout's, thirty seconds.
    """

    deadline_seconds: float = Field(gt=0, le=30)
    post_bytes: int = Field(default=1024 * 1024, ge=1024, le=8 * 1024 * 1024)
    tools: tuple[ArcadeTool, ...] = Field(default=(), max_length=256)
    ungoverned_toolkits: tuple[ToolkitName, ...] = Field(default=(), max_length=64)

    @model_validator(mode="after")
    def declarations_are_unambiguous(self) -> Self:
        """A toolkit is governed or ungoverned, and one tool version is declared once.

        A tool declared twice would make which operation it reaches depend on the order the
        file lists them in. A toolkit named on both sides would govern the tools it declares
        and pass the rest of itself, which is not a decision anyone wrote down.
        """
        declared = [
            (tool.toolkit, tool.name, version) for tool in self.tools for version in tool.versions
        ]
        if len(set(declared)) != len(declared):
            raise ValueError("Duplicate tool declaration")
        ungoverned = set(self.ungoverned_toolkits)
        if len(ungoverned) != len(self.ungoverned_toolkits):
            raise ValueError("Duplicate ungoverned toolkit")
        if ungoverned & {tool.toolkit for tool in self.tools}:
            raise ValueError("A toolkit is governed or ungoverned, never both")
        return self


@dataclass(frozen=True)
class GovernedCall:
    """What one governed hook becomes: the request fields the kernel already defines.

    The declaration supplies the operation and the target's kind, the named input supplies
    the target's value, and the declared argument mapping supplies the arguments. What
    refuses an argument the action does not declare, or a value outside its domain, is the
    resolved action's catalog spec afterwards rather than anything here.

    `claimed_context` carries the incident id where the declaration names one and is the
    empty claim where it does not. Its other four fields — `severity`, `environment`,
    `role` and `criticality` — are never set from a hook: they are facts a contract
    resolves from a trusted source, and a control point asserting one would be reaching
    policy through a surface that evaluates none.
    """

    operation_ref: str
    target: ResourceSelector
    arguments: Arguments
    claimed_context: ClaimedContext = ClaimedContext()


@dataclass(frozen=True)
class UngovernedToolkit:
    """An operator's standing decision that a toolkit passes with no kernel call.

    Operator obligation 5 in docs/ARCADE.md states what it costs: tools the vendor adds to
    the toolkit later pass under the same decision, its enforcement mode is unknown rather
    than integrated, and limitation 7 records that neither the tenant's hash chain nor the
    correlation table can afterwards say how many such calls passed.
    """

    toolkit: str


class ToolMap:
    """One deployment's declarations, indexed for exact lookup.

    A reload never rebuilds one: a file whose block differs from the running one is
    `CONFIGURATION_CHANGED`, so the map a deployment built from its configuration stands
    until a restart. `_Configuration.shape` is what carries that.
    """

    def __init__(self, block: ArcadeBlock) -> None:
        self.block = block
        # The block refuses a duplicate declaration, so one key here names one tool.
        self._governed = {
            (tool.toolkit, tool.name, version): tool
            for tool in block.tools
            for version in tool.versions
        }
        self._ungoverned = frozenset(block.ungoverned_toolkits)

    def decide(
        self,
        *,
        toolkit: str,
        name: str,
        version: str,
        inputs: Mapping[str, object],
        metadata: Mapping[str, object] | None = None,
    ) -> GovernedCall | UngovernedToolkit:
        """The call this hook becomes, or the operator's decision to let its toolkit pass.

        Raises `ToolMapError` for anything else, which is the answer for a tool at a
        version nobody declared as much as for one nobody declared at all.
        """
        declaration = self._governed.get((toolkit, name, version))
        if declaration is None:
            if toolkit in self._ungoverned:
                return UngovernedToolkit(toolkit)
            raise ToolMapError("UNMAPPED_TOOL")
        self._consistent(declaration, metadata)
        if set(inputs) - set(declaration.inputs):
            # Refused before any kernel call: ExecBound decides on the fields the map
            # declares and Arcade executes the whole object, so a key the map does not model
            # could change what the vendor does behind a decision made without it. It fails
            # closed on vendor schema drift, which is the direction a real connector needs.
            raise ToolMapError("UNDECLARED_INPUT")
        try:
            # The one declared key, taken by name, under the kind the operator declared.
            # Whether the value is a string is left to the selector model rather than checked
            # here first: the model is strict, so an absent key, a number, a bool and a
            # nested object all reach this same refusal. A type check ahead of it would
            # answer the same way for each, and an untested guard is worse than none.
            target = ResourceSelector.model_validate(
                {"kind": declaration.target.kind, "value": inputs.get(declaration.target.input)}
            )
        except ValidationError:
            raise ToolMapError("INVALID_TARGET") from None
        claimed = self._claimed(declaration, inputs)
        try:
            # Validated rather than constructed, because an input's value is whatever
            # Arcade sent: `Arguments` is what refuses anything but a bounded scalar here,
            # and the catalog is what refuses a scalar the action does not declare.
            arguments = Arguments.model_validate(
                {
                    argument: inputs[key]
                    for key, argument in declaration.arguments.items()
                    if key in inputs
                }
            )
        except ValidationError:
            raise ToolMapError("INVALID_ARGUMENTS") from None
        return GovernedCall(declaration.operation_ref, target, arguments, claimed)

    @staticmethod
    def _claimed(declaration: ArcadeTool, inputs: Mapping[str, object]) -> ClaimedContext:
        """The incident the agent claims, from the one declared key the operator named.

        A declaration with no `incident` claims nothing, which is the shape a contract
        setting `incident="none"` needs; every context contract the production catalog
        releases sets `incident="required"` instead, so a tool mapped to one of those
        refuses at resolution until an operator declares the key.

        The value is validated through `ClaimedContext` itself, over pydantic's strict JSON
        path as `parse_request` validates the wire body, so what the map admits here is
        what an `ActionRequest` admits and not a second spelling of it. A hook's `inputs`
        values came from JSON, which is what makes re-serializing one total.
        """
        if declaration.incident is None:
            return ClaimedContext()
        try:
            claimed = ClaimedContext.model_validate_json(
                json.dumps({"incident_id": inputs.get(declaration.incident.input)})
            )
        except ValidationError:
            raise ToolMapError("INVALID_INCIDENT") from None
        if claimed.incident_id is None:
            # `incident_id` is optional on the wire, so an absent key and an explicit null
            # both validate to no claim at all. A declaration that names the key is the
            # operator's statement that this tool carries an incident, so the absence is
            # refused here rather than sent on as a request the kernel refuses for a
            # second reason and charges an audited rejection for.
            raise ToolMapError("INVALID_INCIDENT")
        return claimed

    @staticmethod
    def _consistent(declaration: ArcadeTool, metadata: Mapping[str, object] | None) -> None:
        """Deny where the platform's self-description contradicts the operator's map.

        A disagreement about what an action does is the mismatched input the contract denies
        on, and a caller that lies in that direction denies its own action, which charges
        nothing and performs nothing. A report that says nothing about a fact contradicts
        nothing, and one that agrees permits nothing that was not already declared. This is
        the whole of what a report does here: nothing else in this module reads it.

        The comparison is `is not` and not `!=`, which is what makes a second type check
        unnecessary rather than merely unnecessary-looking. `expected` comes from
        `dict[BehaviorFact, bool]`, so it is one of the two `bool` singletons, and identity
        against a singleton is true for that singleton alone: a reported `1` agrees with
        `True` under `==` and denies here, as does a reported string or object. Inside this
        loop the one exemption is `None` — an absent fact or an explicit null — which the
        line above takes, because saying nothing is not a contradiction.
        """
        if not declaration.expect:
            return
        behavior = metadata.get("behavior") if isinstance(metadata, Mapping) else None
        if not isinstance(behavior, Mapping):
            return
        for fact, expected in declaration.expect.items():
            reported = behavior.get(fact)
            if reported is None:
                continue
            if reported is not expected:
                raise ToolMapError("BEHAVIOR_MISMATCH")
