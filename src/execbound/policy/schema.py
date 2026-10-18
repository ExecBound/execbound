# SPDX-License-Identifier: AGPL-3.0-only
"""The Cedar schema a bundle's actions imply, generated from the catalog rather than written.

Every policy pack in the harness builds this same shape by hand: an ``Agent`` principal, one
entity type per resource type carrying the contract's facts as attributes, and one action entry
whose context declares the action's arguments. Hand-writing it is how a schema drifts from the
contract it is supposed to describe, and a rule compiled against a drifted schema is refused by
Cedar for a reason that names neither the rule nor the fact.

So the generator is the single description of the schema, and the rules compiler
(`policy/rulesets.py`) builds every compiled bundle's schema from it.
"""

from collections.abc import Iterable, Mapping

from execbound.audit import canonical_json
from execbound.contracts import ContextContract
from execbound.operations import ActionCatalog

# Present on every resource entity whatever its type: the fence the authorization set compares
# and the account a mapping binds. Neither is a contract fact, and neither may be shadowed by
# one, so a contract declaring either name is a defect rather than an override.
_RESERVED = {"tenant": "String", "account": "String"}


class SchemaError(ValueError):
    """A catalog the generator cannot describe; never a caller's input."""


def entity_attributes(contract: ContextContract) -> dict[str, dict[str, str]]:
    """The attributes this contract gives its Cedar entity, exactly as the schema writes them.

    The one description of an entity: `cedar_schema` emits it, and the rules compiler compares
    it to refuse two mappings that would describe one entity differently, so that early check
    and the schema can never come to disagree about what "differently" means.
    """
    attributes = dict(_RESERVED)
    for fact in contract.facts:
        if fact.name in _RESERVED:
            raise SchemaError(f"Contract fact shadows a reserved attribute: {fact.name}")
        attributes[fact.name] = fact.cedar_type
    return {name: {"type": cedar_type} for name, cedar_type in sorted(attributes.items())}


def _context(action: str, actions: ActionCatalog) -> dict[str, object]:
    spec = actions.action(action)
    if not spec.arguments:
        return {"type": "Record", "attributes": {}}
    return {
        "type": "Record",
        "attributes": {
            "arguments": {
                "type": "Record",
                "attributes": {
                    argument.name: {"type": argument.cedar_type} for argument in spec.arguments
                },
            }
        },
    }


def cedar_schema(
    contracts: Mapping[str, ContextContract],
    *,
    actions: ActionCatalog,
) -> str:
    """The schema for exactly these actions, keyed by action name to its contract.

    Deterministic in the mapping's contents and not in its order: entity types, attributes and
    actions are all emitted sorted, so two callers that resolved the same contracts produce the
    same bytes and a recompile can be compared to stored content directly.
    """
    if not contracts:
        raise SchemaError("No actions to describe")
    entities: dict[str, dict[str, dict[str, str]]] = {}
    for action in sorted(contracts):
        contract = contracts[action]
        attributes = entity_attributes(contract)
        existing = entities.get(contract.cedar_entity_type)
        # Two contracts may share an entity type; they may not disagree about what it holds.
        # Unioning a disagreement would silently widen one contract's facts with another's.
        if existing is not None and existing != attributes:
            raise SchemaError(f"Contracts disagree about entity type: {contract.cedar_entity_type}")
        entities[contract.cedar_entity_type] = attributes
    return canonical_json(
        {
            "ExecBound": {
                "entityTypes": {
                    "Agent": {
                        "shape": {"type": "Record", "attributes": {"tenant": {"type": "String"}}}
                    },
                    **{
                        name: {"shape": {"type": "Record", "attributes": attributes}}
                        for name, attributes in sorted(entities.items())
                    },
                },
                "actions": {
                    action: {
                        "appliesTo": {
                            "principalTypes": ["Agent"],
                            "resourceTypes": [contracts[action].cedar_entity_type],
                            "context": _context(action, actions),
                        }
                    }
                    for action in sorted(contracts)
                },
            }
        }
    )


def entity_type(contracts: Mapping[str, ContextContract], action: str) -> str:
    """The resource entity an action's rules must name, or a schema error."""
    contract = contracts.get(action)
    if contract is None:
        raise SchemaError(f"No contract for action: {action}")
    return contract.cedar_entity_type


def facts(contracts: Mapping[str, ContextContract], action: str) -> Iterable[str]:
    """The fact names a condition on this action may reference."""
    return tuple(fact.name for fact in contracts[action].facts)
