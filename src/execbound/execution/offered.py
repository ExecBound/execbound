# SPDX-License-Identifier: AGPL-3.0-only
"""The operations an agent's own space offers it (#545).

One read serves two callers. `list_actions` lists what it finds, and admission checks a
requested `operation_ref` against the same set before it validates arguments or reads a
target. So an operation another space offers, or one the tenant maps but this space's bundle
does not name, is refused exactly as an unknown one is: the same answer, the same statements
and no record (THREAT_MODEL.md T1.17). Targets, rules, limits and placement are never part of
it. The console's Agents page reads the same set to tell which limit rules bear on an agent,
so a rule is shown for an action the agent can be charged under, by the action its mapping
row serves.
"""

from dataclasses import dataclass
from typing import Literal
from uuid import UUID

from pydantic import Field
from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import SQLAlchemyError

from execbound.audit import canonical_json
from execbound.contracts import Catalog, ContractError
from execbound.db import Database
from execbound.domains import IntegerDomain, StringDomain
from execbound.execution import store
from execbound.execution.models import ExecutionError
from execbound.identity import Identity
from execbound.operations import ArgumentSpec
from execbound.policy.models import BundleContent
from execbound.requests import StrictModel
from execbound.resolution.models import Clock
from execbound.resolution.registry import ResolutionError, mapping_contract
from execbound.spaces import agent_space, is_archived


@dataclass(frozen=True, slots=True)
class OfferedOperation:
    operation_ref: str
    action: str
    resource_type: str
    incident_required: bool


@dataclass(frozen=True, slots=True)
class BundleOperations:
    """What the space's bundle offers, and what else it names that the space cannot use.

    `elsewhere` is what the bundle names through another space's account. `stale` is what it
    names at a reference the tenant's mapping no longer matches (another account, mapping,
    schema or contract version, or the mapping or its account inactive): a policy older than
    its mappings, as a sample removal and reinstall leaves one.
    """

    offered: tuple[OfferedOperation, ...]
    elsewhere: frozenset[str]
    stale: frozenset[str]

    def check(self, operation_ref: str) -> None:
        """Refuse an operation the space does not offer, before arguments are validated or a
        target is read.

        The refusals are told apart only in the audit: `INVALID_CONFIGURATION` when the bundle
        names the operation through another space's account, `INVALID_BUNDLE` when it names
        one at a stale reference (the active bundle cannot authorize it), `INVALID_OPERATION`
        otherwise. All reach the agent as the one 503 every unknown operation gets.
        """
        if any(item.operation_ref == operation_ref for item in self.offered):
            return
        # Each code a literal, so the closed-list check (DN9) reads all three.
        if operation_ref in self.elsewhere:
            raise ResolutionError("INVALID_CONFIGURATION")
        if operation_ref in self.stale:
            raise ResolutionError("INVALID_BUNDLE")
        raise ResolutionError("INVALID_OPERATION")


# One statement whatever is asked: each of the bundle's own mapping references, beside the
# tenant's mapping of that `operation_ref` (at most one: the key is tenant and operation_ref)
# and its account. `current` compares the reference fields the evaluator compares
# (`policy/evaluate.py`), live. A mapping's `action`, when the bundle names one, is not among
# them: the store refuses a bundle whose `action` is not its row's when it validates, activates
# or loads it (`policy/store._components`), and the evaluator denies one, so comparing the
# reference fields shown is enough. `in_space` is the rule `admission._account_in_space`
# applies. The order is by code point, as `BundleContent` and Python order, whatever the
# database's collation.
_OPERATIONS = text(
    """
    SELECT m.operation_ref, om.provider, om.resource_type, om.action, om.provider_operation,
           om.schema_version, om.context_contract_version,
           om.operation_ref IS NOT NULL AS mapped,
           COALESCE(om.account_id = m.account_id AND om.mapping_version = m.mapping_version
             AND om.schema_version = m.schema_version
             AND om.context_contract_version = m.context_contract_version
             AND om.active AND ca.active, false) AS current,
           COALESCE(ca.space_id = :s OR ca.offered_tenant_wide, false) AS in_space
    FROM jsonb_to_recordset(CAST(:mappings AS jsonb)) AS m(
      operation_ref text, account_id uuid, mapping_version text, schema_version text,
      context_contract_version text)
    LEFT JOIN execbound.operation_mappings om
      ON om.tenant_id = :t AND om.operation_ref = m.operation_ref
    LEFT JOIN execbound.connector_accounts ca ON ca.tenant_id = om.tenant_id
      AND ca.account_id = om.account_id AND ca.provider = om.provider
    ORDER BY m.operation_ref COLLATE "C"
    """
)


def bundle_operations(
    conn: Connection, tenant: UUID, space: UUID, bundle: BundleContent, *, catalog: Catalog
) -> BundleOperations:
    """The operations `bundle` offers `space`, in `operation_ref` order.

    A reference the tenant does not map at all is none of the three: it is unknown. A stale
    reference is stale whichever space its account is in, because the bundle could not
    authorize it anywhere. A current mapping whose tuple the catalog no longer binds, or whose
    context contract it no longer holds, is not offered either: resolution would refuse it as
    `INVALID_OPERATION` anyway. A bundle never names one `operation_ref` twice
    (`BundleContent` refuses it).
    """
    references = [
        {
            "operation_ref": mapping.operation_ref,
            "account_id": str(mapping.account_id),
            "mapping_version": mapping.mapping_version,
            "schema_version": mapping.schema_version,
            "context_contract_version": mapping.context_contract_version,
        }
        for mapping in bundle.mappings
    ]
    offered: list[OfferedOperation] = []
    elsewhere: set[str] = set()
    stale: set[str] = set()
    rows = conn.execute(
        _OPERATIONS, {"t": tenant, "s": space, "mappings": canonical_json(references)}
    ).mappings()
    for row in rows:
        operation_ref = str(row["operation_ref"])
        if not row["mapped"]:
            continue
        if not row["current"]:
            stale.add(operation_ref)
            continue
        if not row["in_space"]:
            elsewhere.add(operation_ref)
            continue
        try:
            spec = mapping_contract(dict(row), catalog=catalog)
            contract = catalog.for_operation(
                row["context_contract_version"], spec.action, spec.resource_type
            )
        except (ResolutionError, ContractError, KeyError, TypeError):
            continue
        offered.append(
            OfferedOperation(
                operation_ref=operation_ref,
                action=spec.action,
                resource_type=spec.resource_type,
                incident_required=contract.incident == "required",
            )
        )
    return BundleOperations(
        offered=tuple(offered), elsewhere=frozenset(elsewhere), stale=frozenset(stale)
    )


ArgumentType = Literal["string", "integer", "boolean"]
TargetKind = Literal["canonical", "hostname", "provider_id"]


class ListedArgument(StrictModel):
    """One argument the action takes, with the values or range it accepts."""

    name: str
    type: ArgumentType
    values: tuple[str, ...] | None = Field(
        default=None, description="Present for a string argument: every value it accepts."
    )
    minimum: int | None = Field(
        default=None, description="Present for an integer argument: the least value it accepts."
    )
    maximum: int | None = Field(
        default=None,
        description="Present for an integer argument: the greatest value it accepts.",
    )


class ListedAction(StrictModel):
    """One operation the agent's space offers. A listed action is not permission."""

    operation_ref: str = Field(description="What to send as `operation_ref`.")
    action: str = Field(description="The catalog action it performs.")
    label: str = Field(description="The catalog action's one-line name.")
    arguments: tuple[ListedArgument, ...] = Field(
        description="Every argument it takes; send exactly these, each within its domain."
    )
    target_kinds: tuple[TargetKind, ...] = Field(description="The `target.kind` values it accepts.")
    incident_required: bool = Field(
        description="Whether `claimed_context.incident_id` must name an incident on the target."
    )


class ActionListing(StrictModel):
    """What `list_actions` and `GET /v1/actions` answer: never a target, a rule or a limit."""

    actions: tuple[ListedAction, ...]


def _argument(spec: ArgumentSpec) -> ListedArgument:
    if isinstance(spec.domain, StringDomain):
        return ListedArgument(
            name=spec.name, type="string", values=tuple(sorted(spec.domain.values))
        )
    if isinstance(spec.domain, IntegerDomain):
        return ListedArgument(
            name=spec.name, type="integer", minimum=spec.domain.minimum, maximum=spec.domain.maximum
        )
    return ListedArgument(name=spec.name, type="boolean")


def _listed(item: OfferedOperation, catalog: Catalog) -> ListedAction:
    spec = catalog.actions.action(item.action)
    # An identity action refuses a hostname (`registry.resource`, `snapshot.py`).
    kinds: tuple[TargetKind, ...] = (
        ("canonical", "provider_id")
        if item.resource_type == "identity"
        else ("canonical", "hostname", "provider_id")
    )
    return ListedAction(
        operation_ref=item.operation_ref,
        action=spec.action,
        label=spec.label,
        arguments=tuple(_argument(argument) for argument in spec.arguments),
        target_kinds=kinds,
        incident_required=item.incident_required,
    )


def action_listing(offered: tuple[OfferedOperation, ...], catalog: Catalog) -> ActionListing:
    """The answer for an offered set, in the order `bundle_operations` read it."""
    return ActionListing(actions=tuple(_listed(item, catalog) for item in offered))


def listing(db: Database, identity: Identity, clock: Clock, *, catalog: Catalog) -> ActionListing:
    """What the agent's own space offers it, read without the fence (it changes nothing) and
    in one snapshot, so every statement sees the same instant.

    Only `offered` is listed: what the bundle names through another space's account, or at a
    stale reference, is refused as unknown and never listed. An archived space is refused as
    `execute` refuses it; a space with no active policy lists nothing; an emergency stop does
    not stop a listing, as it does not stop a status read.
    """
    try:
        with db.transaction(identity.tenant_id, snapshot=True) as conn:
            store.identity_check(conn, identity, clock, "AGENT")
            space = agent_space(conn, identity.tenant_id, identity.principal_id)
            if is_archived(conn, identity.tenant_id, space):
                raise ExecutionError("SPACE_ARCHIVED")
            offered: tuple[OfferedOperation, ...] = ()
            try:
                bundle = store.active_bundle(conn, identity.tenant_id, space)
            except ExecutionError as exc:
                if exc.code != "NO_ACTIVE_BUNDLE":
                    raise
            else:
                offered = bundle_operations(
                    conn, identity.tenant_id, space, bundle, catalog=catalog
                ).offered
            store.identity_check(conn, identity, clock, "AGENT")
        return action_listing(offered, catalog)
    except ExecutionError:
        raise
    except (SQLAlchemyError, ValueError):
        raise ExecutionError() from None
