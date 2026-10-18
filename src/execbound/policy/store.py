# SPDX-License-Identifier: AGPL-3.0-only
"""Digest-bound content and atomic, tenant-scoped administrative lifecycle.

The mutation functions return immutable BundleRecord(content, state) snapshots.
load_active_bundle returns BundleContent, or raises PolicyStoreError when no usable
active bundle exists. These internal primitives expose no route and never dispatch.
"""

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal, cast
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import SQLAlchemyError

from execbound.access_control import access_visibility, has_permission
from execbound.audit import acted_with, append_event, canonical_json
from execbound.contracts import (
    PRODUCTION_CATALOG,
    Catalog,
    ContractError,
    Signal,
    validate_bundle_contracts,
    validate_selector,
)
from execbound.db import Database, check_runtime
from execbound.identity import Identity
from execbound.operations import PRODUCTION_ACTIONS, CatalogError
from execbound.policy.cedar import (
    CedarValidationError,
    approval_policy_ids,
    validate_policy_sets,
)
from execbound.policy.models import BundleContent, Ruleset
from execbound.policy.rulesets import RulesetError, compile_ruleset, ruleset_bundle
from execbound.provider.published_keys import PUBLISHED_EXECUTOR_KEYS
from execbound.resolution.models import Clock, SystemClock
from execbound.resolution.registry import ResolutionError, mapping, mapping_contract
from execbound.secrets import find_secrets, secret_shaped
from execbound.signals.capabilities import capability as signal_capability
from execbound.spaces import Visibility, default_space, is_archived, space_clause

BundleState = Literal["DRAFT", "VALIDATED", "ACTIVE", "RETIRED"]


class PolicyStoreError(ValueError):
    """Safe dependency/identity/state error; no policy or database diagnostics."""

    def __init__(self, code: str = "POLICY_UNAVAILABLE", *, location: str | None = None) -> None:
        self.code = code
        self.location = location
        super().__init__("Policy store unavailable")


@dataclass(frozen=True)
class BundleRecord:
    content: BundleContent
    state: BundleState


@dataclass(frozen=True)
class BundleSummary:
    bundle_id: UUID
    content_hash: str
    state: BundleState
    changed_at: datetime
    active: bool


# Whether the tenant holds a key that could attest a grant issued now. One spelling for the
# two owner-connection guards that ask it — this module, validating a bundle that declares
# an external executor, and `administration._keep_attestable`, refusing to retire the last
# such key while that bundle is active — because they are the same question about the same
# rows and a second spelling is how the two come to disagree. Admission asks a stronger
# question of the composition boundary (`runtime.attestable_ring`), because a row this
# predicate counts may still be one the ring loader refuses.
#
# A published test key is not a live key, because it attests nothing (`provider.published_keys`),
# so a bundle is not validated on one and the last key of the tenant's own is not retired
# beside one. The list is that module's, written as SQL literals: every entry is lowercase hex,
# which that module refuses to load without, and nothing from a caller reaches this string.
_PUBLISHED_EXECUTOR_KEYS = ", ".join(f"'{key}'" for key in sorted(PUBLISHED_EXECUTOR_KEYS))
LIVE_EXECUTOR_KEY = (
    "SELECT 1 FROM execbound.executor_keys WHERE tenant_id = :tenant AND revoked_at IS NULL "  # nosec B608 - literals from a hex-only constant
    f"AND public_key NOT IN ({_PUBLISHED_EXECUTOR_KEYS}) LIMIT 1"
)

# Each owner-provisioned lookup is a fixed literal chosen by (table, column); caller strings
# are never interpolated. An account must also be active, as a mapping's account must be.
Authority = Literal["group", "account", "executor", "space"]
_AUTHORITY_LOOKUPS: dict[Authority, str] = {
    "group": (
        "SELECT 1 FROM execbound.principal_groups WHERE tenant_id = :tenant AND group_id = :value"
    ),
    # A `space` rule names an existing space of this tenant. An archived space keeps its
    # rules: the archive stops new work and loses no history, so a rule over it still
    # counts what it counted.
    "space": "SELECT 1 FROM execbound.spaces WHERE tenant_id = :tenant AND space_id = :value",
    "account": (
        "SELECT 1 FROM execbound.connector_accounts "
        "WHERE tenant_id = :tenant AND account_id = :value AND active"
    ),
    # A revoked key can still verify a proof for a grant issued while it was current, but it
    # cannot verify a new one, so a tenant whose every key is revoked has no executor.
    "executor": LIVE_EXECUTOR_KEY,
}
# Authorities that ask only whether the tenant has any such row, so they name no qualifier.
_TENANT_WIDE: frozenset[Authority] = frozenset({"executor"})


def _now(clock: Clock) -> datetime:
    now = clock.now()
    if now.tzinfo is None or now.utcoffset() is None:
        raise PolicyStoreError("INVALID_CLOCK")
    return now.astimezone(UTC)


def _identity(
    conn: Connection,
    identity: Identity,
    clock: Clock,
    *,
    admin: bool,
    permission: str | None = None,
) -> None:
    from execbound.access_control import has_permission, is_managed

    now = _now(clock)
    if (
        identity.kind not in {"AGENT", "HUMAN_APPROVER", "ADMIN"}
        or (admin and permission is None and identity.kind != "ADMIN")
        or identity.expires_at.tzinfo is None
        or identity.expires_at <= now
    ):
        raise PolicyStoreError("INVALID_IDENTITY")
    expiry = conn.execute(
        text("""
        SELECT c.expires_at FROM execbound.credentials c
        JOIN execbound.principals p USING (tenant_id, principal_id)
        JOIN execbound.tenants t USING (tenant_id)
        WHERE c.tenant_id = :tenant AND c.principal_id = :principal
          AND c.credential_id = :credential AND c.revoked_at IS NULL
          AND c.issued_at <= :now AND c.expires_at > :now
          AND execbound.access_effective_kind(p.principal_id) = :kind AND p.active AND t.active
    """),
        {
            "tenant": identity.tenant_id,
            "principal": identity.principal_id,
            "credential": identity.credential_id,
            "now": now,
            "kind": identity.kind,
        },
    ).scalar_one_or_none()
    if expiry is None or expiry != identity.expires_at or expiry <= _now(clock):
        raise PolicyStoreError("INVALID_IDENTITY")
    if admin and not has_permission(
        conn,
        identity.tenant_id,
        identity.principal_id,
        permission or "workspace.manage",
        any_scope=True,
    ):
        raise PolicyStoreError("INVALID_IDENTITY")
    if (
        identity.kind != "AGENT"
        and is_managed(conn, identity.tenant_id, identity.principal_id)
        and not has_permission(
            conn, identity.tenant_id, identity.principal_id, "console.read", any_scope=True
        )
    ):
        raise PolicyStoreError("INVALID_IDENTITY")


def _known(conn: Connection, authority: Authority, tenant: UUID, value: UUID | None = None) -> bool:
    """Whether the tenant has this owner-provisioned row; a rule without its qualifier has none."""
    params: dict[str, UUID] = {"tenant": tenant}
    if authority not in _TENANT_WIDE:
        if value is None:
            return False
        params["value"] = value
    found = conn.execute(text(_AUTHORITY_LOOKUPS[authority]), params).scalar_one_or_none()
    return found is not None


def _read(conn: Connection, tenant: UUID, bundle_id: UUID, *, lock: bool) -> BundleRecord:
    suffix = " FOR UPDATE OF s" if lock else ""
    # suffix is one of two literals; tenant and bundle are bound parameters.
    row = (
        conn.execute(
            text(
                """
        SELECT b.content, b.content_hash, s.state FROM execbound.policy_bundle_contents b
        JOIN execbound.policy_bundle_lifecycle s USING (tenant_id, bundle_id, content_hash)
        WHERE b.tenant_id = :tenant AND b.bundle_id = :bundle
    """
                + suffix  # nosec B608 - one of two literals; tenant and bundle are bound
            ),
            {"tenant": tenant, "bundle": bundle_id},
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise PolicyStoreError("INVALID_BUNDLE")
    # JSON mode retains strict field validation while decoding UUID strings and tuples.
    content = BundleContent.model_validate_json(canonical_json(row["content"]))
    if (
        content.tenant_id != tenant
        or content.bundle_id != bundle_id
        or content.content_hash != row["content_hash"]
        or row["state"] not in {"DRAFT", "VALIDATED", "ACTIVE", "RETIRED"}
    ):
        raise PolicyStoreError("INVALID_BUNDLE")
    return BundleRecord(content, row["state"])


def _checkpoint(row: dict[str, Any], index: int, *, attestable: bool) -> None:
    """Refuse a checkpoint mapping the released catalog or the tenant cannot support.

    The released catalog, not the caller's, decides which operations may be executed outside
    ExecBound: the executor acts against that exact vendor operation and the settled record
    names it, so a narrowed or extended catalog must never widen what a grant may describe.
    The whole tuple is checked, not just that some binding exists, because a grant that named
    a different provider operation would describe an action nobody authorized. A tenant with
    no unrevoked executor key can attest no outcome and has no administrator exit for a grant
    nobody reports, so its bundle cannot declare one.
    """
    location = f"mappings.{index}.external_executor"
    try:
        PRODUCTION_ACTIONS.validate_operation(
            provider=row["provider"],
            resource_type=row["resource_type"],
            action=row["action"],
            provider_operation=row["provider_operation"],
            schema_version=row["schema_version"],
        )
    except CatalogError:
        raise PolicyStoreError("INVALID_COMPONENT", location=location) from None
    if not attestable:
        raise PolicyStoreError("INVALID_COMPONENT", location=location)


def _ruleset(content: BundleContent, catalog: Catalog) -> None:
    """A bundle carrying a ruleset must hold exactly what that ruleset compiles to.

    This is the whole safety story for rulesets, and it is why the compiler can sit outside the
    security boundary: the kernel keeps reading the compiled components, and a bundle whose
    components say something its rules do not is refused before it can ever be active.

    Deliberately not called from ``load_active_bundle``. That path runs on every admission, and
    putting a compile on it would both cost a recompile per request and make the kernel depend
    on the compiler at decision time. Bundle content is immutable once created, so checking at
    validation and again at activation covers every way content reaches the ACTIVE state.
    """
    if content.ruleset is None:
        return
    try:
        compiled = compile_ruleset(content.ruleset, content.mappings, catalog=catalog)
    except RulesetError as error:
        raise PolicyStoreError("RULESET_MISMATCH", location=error.location) from None
    for name, expected in (
        ("cedar_schema", compiled.cedar_schema),
        ("authorization_policies", compiled.authorization_policies),
        ("approval_policies", compiled.approval_policies),
        ("limits", compiled.limits),
        ("quorum", compiled.quorum),
    ):
        # The component name is the location, so a refusal says which one disagreed rather
        # than only that something did.
        if getattr(content, name) != expected:
            raise PolicyStoreError("RULESET_MISMATCH", location=name)


def _components(conn: Connection, content: BundleContent, catalog: Catalog) -> None:
    try:
        validate_policy_sets(
            schema=content.cedar_schema,
            authorization=content.authorization_policies,
            approval=content.approval_policies,
        )
    except CedarValidationError as error:
        # Cedar refusing the bundle's own text is a defect in that component, named like
        # any other; only an engine that failed outright leaves the store unavailable.
        if error.component is None:
            raise PolicyStoreError() from None
        raise PolicyStoreError("INVALID_COMPONENT", location=error.component) from None
    if content.quorum:
        known = {
            f"policy:{policy_id}"
            for policy_id in approval_policy_ids(
                schema=content.cedar_schema, approval=content.approval_policies
            )
        } | {
            f"limit:{rule.rule_id}"
            for rule in content.limits
            if rule.on_exceed == "REQUIRE_APPROVAL"
        }
        for index, rule in enumerate(content.quorum):
            if rule.obligation not in known:
                raise PolicyStoreError("INVALID_COMPONENT", location=f"quorum.{index}.obligation")
    contracts = []
    operations = []
    # One lookup for the bundle, not one per mapping: this runs on every admission through
    # load_active_bundle, and a bundle may carry up to sixty-four mappings.
    attestable = any(m.external_executor for m in content.mappings) and _known(
        conn, "executor", content.tenant_id
    )
    for index, reference in enumerate(content.mappings):
        try:
            # A missing, inactive or catalog-mismatched mapping is a defect in this
            # bundle's components, not an unavailable store.
            current = mapping(conn, content.tenant_id, reference.operation_ref, catalog=catalog)
            if any(
                current[field] != getattr(reference, field)
                for field in (
                    "account_id",
                    "mapping_version",
                    "schema_version",
                    "context_contract_version",
                )
            ):
                raise PolicyStoreError("INVALID_COMPONENT", location=f"mappings.{index}")
            if reference.action is not None and reference.action != current["action"]:
                # A mapping that names its action names the one its row serves; the row, not
                # the bundle, decides what a ref dispatches.
                raise PolicyStoreError("INVALID_COMPONENT", location=f"mappings.{index}.action")
            if content.ruleset is not None and reference.action_name != current["action"]:
                # Rules compile about a mapping's `action_name`, so a rules bundle whose ref is
                # the name of another action than its row serves would compile policy about
                # the wrong action. A hand-written bundle is read by its row, as it always was.
                raise PolicyStoreError("INVALID_COMPONENT", location=f"mappings.{index}.action")
            if reference.observe_only and reference.external_executor:
                # The model refuses this, but an observed request reserves nothing and a
                # grant must reserve, so the store does not rely on that alone.
                raise PolicyStoreError(
                    "INVALID_COMPONENT", location=f"mappings.{index}.external_executor"
                )
            if reference.external_executor:
                # The row's own tuple, so the checks read what this tenant's registry
                # currently binds rather than what the bundle claims about it.
                _checkpoint(current, index, attestable=attestable)
            operations.append(mapping_contract(current, catalog=catalog))
            contracts.append(
                catalog.for_operation(
                    current["context_contract_version"], current["action"], current["resource_type"]
                )
            )
        except (ResolutionError, ContractError):
            raise PolicyStoreError("INVALID_COMPONENT") from None
    for index, limit_rule in enumerate(content.limits):
        # A rule naming an action outside the catalog, a group or account the tenant does
        # not have, or a fact its plans will not carry would never charge or cap anything,
        # so the store refuses to validate or activate the bundle.
        try:
            for name in limit_rule.action_names:
                catalog.actions.action(name)
        except CatalogError:
            raise PolicyStoreError("INVALID_COMPONENT", location=f"limits.{index}.action") from None
        if limit_rule.scope == "group" and not _known(
            conn, "group", content.tenant_id, limit_rule.group_id
        ):
            raise PolicyStoreError("INVALID_COMPONENT", location=f"limits.{index}.group_id")
        if limit_rule.scope == "account" and not _known(
            conn, "account", content.tenant_id, limit_rule.account_id
        ):
            raise PolicyStoreError("INVALID_COMPONENT", location=f"limits.{index}.account_id")
        if limit_rule.scope == "space" and not _known(
            conn, "space", content.tenant_id, limit_rule.space_id
        ):
            raise PolicyStoreError("INVALID_COMPONENT", location=f"limits.{index}.space_id")
        if limit_rule.scope == "selector":
            # Gate on the scope, not the qualifier, so a copy without its selector fails closed.
            if limit_rule.selector is None:
                raise PolicyStoreError("INVALID_COMPONENT", location=f"limits.{index}.selector")
            try:
                validate_selector(
                    contracts=contracts,
                    actions=limit_rule.action_names,
                    fact=limit_rule.selector.fact,
                    equals=limit_rule.selector.equals,
                )
            except ContractError:
                raise PolicyStoreError(
                    "INVALID_COMPONENT", location=f"limits.{index}.selector"
                ) from None
    try:
        validate_bundle_contracts(
            contracts=contracts,
            cedar_schema=content.cedar_schema,
            settings=content.context_settings,
            operations=operations,
        )
    except ContractError:
        raise PolicyStoreError("INVALID_COMPONENT") from None


def _signal_mappings(
    conn: Connection, content: BundleContent, catalog: Catalog, *, selecting: UUID | None
) -> None:
    """Refuse a signal mapping the bundle's space, a registration or liveness cannot support.

    Validation and activation only, never `load_active_bundle`: a source revoked after
    activation fails its facts closed at resolution rather than taking the whole bundle
    down. `selecting` is the space activating the bundle, which both activations always
    pass; validation passes None, because no space is selecting anything yet. Offering a
    bundle tenant-wide has no application path today (only owner SQL sets
    `offered_tenant_wide`); when one is written, it must call this too.
    """
    mapped = {reference.context_contract_version for reference in content.mappings}
    for version in sorted(mapped):
        for spec in catalog.contract(version).facts:
            if isinstance(spec.storage, Signal) and (
                content.signal_mapping(version, spec.storage.capability) is None
            ):
                # Every request on this contract would be INVALID_CONTEXT: safe, and baffling.
                raise PolicyStoreError("INVALID_COMPONENT", location="signal_mappings")
    if not content.signal_mappings:
        return
    owner = (
        conn.execute(
            text(
                "SELECT space_id, offered_tenant_wide FROM execbound.policy_bundle_contents "
                "WHERE tenant_id = :t AND bundle_id = :b"
            ),
            {"t": content.tenant_id, "b": content.bundle_id},
        )
        .mappings()
        .one()
    )
    for index, entry in enumerate(content.signal_mappings):
        location = f"signal_mappings.{index}"
        if entry.context_contract_version not in mapped:
            raise PolicyStoreError("INVALID_COMPONENT", location=location)
        contract = catalog.contract(entry.context_contract_version)
        if not any(
            isinstance(spec.storage, Signal) and spec.storage.capability == entry.capability
            for spec in contract.facts
        ):
            raise PolicyStoreError("INVALID_COMPONENT", location=f"{location}.capability")
        declared = signal_capability(entry.capability)
        clean = [i for i, row in enumerate(entry.thresholds) if row.value == declared.clean]
        for position, source in enumerate(entry.admitted_sources):
            where = f"{location}.admitted_sources.{position}"
            # Named columns: the runtime role cannot read the token digests. The source's
            # `expires_at` is deliberately not read: expiry belongs to the current token, a
            # rotation revives the source, and `signal_admit` and each record's freshness
            # already bound what an expired token can contribute. Health is never an input to
            # authority.
            row = (
                conn.execute(
                    text(
                        "SELECT space_id, offered_tenant_wide, capabilities, subject_kinds, "
                        "input_path, attests_liveness, active, revoked_at "
                        "FROM execbound.signal_sources WHERE tenant_id = :t AND source_id = :s"
                    ),
                    {"t": content.tenant_id, "s": source},
                )
                .mappings()
                .one_or_none()
            )
            if (
                row is None
                or not row["active"]
                or row["revoked_at"] is not None
                or entry.capability not in row["capabilities"]
                or declared.subject not in row["subject_kinds"]
                # A required mapping admits only a source the agent cannot feed.
                or (entry.mode == "required" and row["input_path"] != "independent")
                # A capability with no `no_detection` value has nothing a source that cannot
                # attest liveness may report when it sees nothing, so it cannot take that
                # source as a required input.
                or (not row["attests_liveness"] and declared.no_detection is None)
                # Usable by the bundle's own space, by every space if the bundle is offered,
                # and by the space activating it.
                or not (row["offered_tenant_wide"] or row["space_id"] == owner["space_id"])
                or (owner["offered_tenant_wide"] and not row["offered_tenant_wide"])
                or (
                    selecting is not None
                    and not (row["offered_tenant_wide"] or row["space_id"] == selecting)
                )
            ):
                raise PolicyStoreError("INVALID_COMPONENT", location=where)
            if clean and not row["attests_liveness"]:
                # Silence, or a sensor that stopped reporting, never reads as clean.
                raise PolicyStoreError(
                    "INVALID_COMPONENT", location=f"{location}.thresholds.{clean[0]}"
                )


def _audit(
    conn: Connection,
    identity: Identity,
    content: BundleContent,
    transition: str,
    *,
    space: UUID | None = None,
    reason: str | None = None,
) -> None:
    """One lifecycle event. `activated`, `deselected` and `retired` carry the space they
    happened in, which changes future bytes only: a retained event is re-hashed from its
    own retained bytes, so nothing already in a chain moves. Each also names the credential
    that acted (`acted_with`). An activation given a person's reason carries it as `reason`;
    one given none writes the payload it always did, so the key is never written empty."""
    payload: dict[str, Any] = {
        "bundle_id": str(content.bundle_id),
        "content_hash": content.content_hash,
        **acted_with(identity.credential_id),
    }
    if space is not None:
        payload["space_id"] = str(space)
    if reason is not None:
        payload["reason"] = reason
    append_event(
        conn,
        identity.tenant_id,
        identity.principal_id,
        f"policy.bundle_{transition}",
        payload,
        space=space,
    )


def _bundle_space(conn: Connection, tenant: UUID, bundle_id: UUID) -> UUID:
    """The space that owns one bundle; a successor draft keeps the space it replaces."""
    space = conn.execute(
        text(
            "SELECT space_id FROM execbound.policy_bundle_contents "
            "WHERE tenant_id = :tenant AND bundle_id = :bundle"
        ),
        {"tenant": tenant, "bundle": bundle_id},
    ).scalar_one_or_none()
    if space is None:
        raise PolicyStoreError("INVALID_BUNDLE")
    return UUID(str(space))


def _selected_anywhere(conn: Connection, tenant: UUID, bundle_id: UUID) -> bool:
    """Whether any space of the tenant still selects this bundle; `ACTIVE` means exactly this."""
    return (
        conn.execute(
            text(
                "SELECT 1 FROM execbound.space_policy_selection "
                "WHERE tenant_id = :tenant AND bundle_id = :bundle LIMIT 1"
            ),
            {"tenant": tenant, "bundle": bundle_id},
        ).scalar_one_or_none()
        is not None
    )


def _selected_in(conn: Connection, tenant: UUID, space: UUID) -> UUID | None:
    """The bundle one space selects, or None; read under the caller's fence."""
    found = conn.execute(
        text("""
        SELECT bundle_id FROM execbound.space_policy_selection
        WHERE tenant_id = :tenant AND space_id = :space
    """),
        {"tenant": tenant, "space": space},
    ).scalar_one_or_none()
    return None if found is None else UUID(str(found))


def _select(
    conn: Connection, identity: Identity, space: UUID, bundle_id: UUID, clock: Clock
) -> None:
    """Make one bundle the space's selection, replacing the one it had.

    The one place a selection is written, so the two activations cannot come to disagree
    about what selecting records. `activate_new_bundle` has already refused a space that
    selects anything, under the same fence, so for it nothing is ever replaced.
    """
    conn.execute(
        text("""
        INSERT INTO execbound.space_policy_selection
          (tenant_id, space_id, bundle_id, changed_at, changed_by)
        VALUES (:tenant, :space, :bundle, :now, :actor)
        ON CONFLICT (tenant_id, space_id) DO UPDATE
          SET bundle_id = excluded.bundle_id, changed_at = excluded.changed_at,
              changed_by = excluded.changed_by
    """),
        {
            "tenant": identity.tenant_id,
            "space": space,
            "bundle": bundle_id,
            "now": _now(clock),
            "actor": identity.principal_id,
        },
    )


def _state(conn: Connection, content: BundleContent, state: BundleState, clock: Clock) -> None:
    conn.execute(
        text("""
        UPDATE execbound.policy_bundle_lifecycle SET state = :state, changed_at = :now
        WHERE tenant_id = :tenant AND bundle_id = :bundle
    """),
        {
            "tenant": content.tenant_id,
            "bundle": content.bundle_id,
            "state": state,
            "now": _now(clock),
        },
    )


_BRACKET_INDEX = re.compile(r"\[(\d+)\]")


def _dotted(path: str) -> str:
    """`find_secrets`' bracketed list index, in the dotted form the rules route's own body
    errors and the compiler's `RulesetError` already use for a ruleset location:
    `rules[0].note` becomes `rules.0.note`."""
    return _BRACKET_INDEX.sub(r".\1", path)


def _insert_draft(
    conn: Connection,
    identity: Identity,
    content: BundleContent,
    clock: Clock,
    space: UUID | None = None,
) -> None:
    """Write one immutable DRAFT content with its lifecycle row and its audit events.

    The one place a draft is written, so `create_bundle` and `change_draft_rules` cannot
    come to disagree about what creating one records. Content is insert-only here because it
    is insert-only in the database: `execbound_app` is granted `SELECT, INSERT` on
    `policy_bundle_contents` and no `UPDATE` or `DELETE` at all, which is why editing a
    draft's rules writes a successor rather than rewriting a row.
    """
    # The replay export carries every bundle an event references, drafts never validated
    # included, and refuses all of it if one holds text shaped like a secret; such a draft
    # is refused here, where it is written, naming the place and never the value. A bundle
    # written as rules is screened there first: every component the dump below carries
    # before `ruleset` — the Cedar texts, `limits` and `quorum` — is the compiler's own
    # copy of what `ruleset` already says, at a different path, and a person can only find
    # and fix the one they actually wrote. Not on `BundleContent`, which every read
    # validates again: a stored bundle holding such text would become unreadable and stop
    # the tenant's admission.
    dumped = content.model_dump(mode="json")
    ruleset_dump = dumped.get("ruleset")
    if ruleset_dump is not None:
        found = find_secrets(ruleset_dump, limit=1)
        if found:
            raise PolicyStoreError("INVALID_TEXT", location=f"ruleset.{_dotted(found[0].path)}")
    found = find_secrets(dumped, limit=1)
    if found:
        raise PolicyStoreError("INVALID_TEXT", location=_dotted(found[0].path))
    params = {
        "tenant": content.tenant_id,
        "bundle": content.bundle_id,
        "digest": content.content_hash,
        "content": content.model_dump_json(),
        "now": _now(clock),
        "actor": identity.principal_id,
        # A bundle is owned by one space and may be offered tenant-wide; a caller that
        # named none writes in the tenant's only space.
        "space": space or default_space(conn, content.tenant_id),
    }
    conn.execute(
        text("""
        INSERT INTO execbound.policy_bundle_contents
          (tenant_id, bundle_id, content_hash, content, created_at, created_by, space_id)
        VALUES (:tenant, :bundle, :digest, CAST(:content AS jsonb), :now, :actor, :space)
    """),
        params,
    )
    conn.execute(
        text("""
        INSERT INTO execbound.policy_bundle_lifecycle
          (tenant_id, bundle_id, content_hash, state, changed_at)
        VALUES (:tenant, :bundle, :digest, 'DRAFT', :now)
    """),
        params,
    )
    _audit(conn, identity, content, "created")
    if content.ruleset is not None:
        # Beside the lifecycle event, not instead of it: the chain records that this
        # content was compiled from rules, with counts and never the rules' text.
        append_event(
            conn,
            identity.tenant_id,
            identity.principal_id,
            "policy.ruleset_compiled",
            {
                "bundle_id": str(content.bundle_id),
                "content_hash": content.content_hash,
                "rules": len(content.ruleset.rules),
                "budgets": len(content.ruleset.budgets),
                **acted_with(identity.credential_id),
            },
        )


def _creation_scope(
    conn: Connection,
    identity: Identity,
    content: BundleContent,
    space: UUID | None,
    source_bundle_id: UUID | None,
) -> UUID:
    """Recheck draft ownership and any copied source inside the draft's transaction."""
    selected = space or default_space(conn, identity.tenant_id)
    everything, spaces, roles = access_visibility(conn, identity.tenant_id, identity.principal_id)
    visibility = Visibility(
        everything=everything,
        spaces=spaces,
        current=selected,
        roles=roles,
    )
    if not has_permission(
        conn, identity.tenant_id, identity.principal_id, "policy.manage", selected
    ):
        raise PolicyStoreError("INVALID_IDENTITY")
    if is_archived(conn, identity.tenant_id, selected):
        raise PolicyStoreError("SPACE_ARCHIVED")
    if source_bundle_id is not None:
        # Only fixed predicates and literal aliases; request values remain bound.
        source = space_clause(visibility, "c", offered=True)
        found = conn.execute(
            text(
                "SELECT 1 FROM execbound.policy_bundle_contents c "
                "WHERE c.tenant_id=:t AND c.bundle_id=:b" + source.sql  # nosec B608 - fixed predicate; all values bound
            ),
            {"t": identity.tenant_id, "b": source_bundle_id, **source.params},
        ).scalar_one_or_none()
        if found is None:
            raise PolicyStoreError("INVALID_BUNDLE")
    accounts = space_clause(visibility, "a", offered=True)
    params = {
        "t": identity.tenant_id,
        "accounts": [str(mapping.account_id) for mapping in content.mappings],
    }
    statement = (
        "SELECT a.account_id FROM execbound.connector_accounts a WHERE a.tenant_id=:t "
        "AND a.account_id=ANY(CAST(:accounts AS uuid[]))"
    )
    existing = set(conn.execute(text(statement), params).scalars())
    allowed = set(
        conn.execute(text(statement + accounts.sql), {**params, **accounts.params}).scalars()
    )
    # An unknown account is a component-validation problem. A known private account from
    # another Space must never enter a draft, including one imported as a document.
    if existing - allowed:
        raise PolicyStoreError("INVALID_BUNDLE")
    return selected


def _policy_identity(conn: Connection, identity: Identity, clock: Clock) -> None:
    # Read and mutation callers share the tenant fence with role changes. Revocation
    # cannot commit between the authoritative recheck and a policy write.
    from execbound.execution.store import fence

    fence(conn, identity.tenant_id, clock)
    _identity(conn, identity, clock, admin=True, permission="policy.manage")


def _bundle_access(conn: Connection, identity: Identity, bundle_id: UUID, *, write: bool) -> UUID:
    row = conn.execute(
        text(
            "SELECT space_id,offered_tenant_wide FROM execbound.policy_bundle_contents "
            "WHERE tenant_id=:t AND bundle_id=:b"
        ),
        {"t": identity.tenant_id, "b": bundle_id},
    ).one_or_none()
    if row is None or not (
        has_permission(
            conn, identity.tenant_id, identity.principal_id, "policy.manage", row.space_id
        )
        or (
            not write
            and row.offered_tenant_wide
            and has_permission(
                conn, identity.tenant_id, identity.principal_id, "policy.manage", any_scope=True
            )
        )
    ):
        raise PolicyStoreError("INVALID_BUNDLE")
    return cast(UUID, row.space_id)


def create_bundle(
    db: Database,
    identity: Identity,
    content: BundleContent,
    clock: Clock | None = None,
    *,
    space: UUID | None = None,
    source_bundle_id: UUID | None = None,
) -> BundleRecord:
    """Create immutable DRAFT content; validation is a separate audited transition.

    The draft is owned by one space: the one the administrator is looking at, or the
    tenant's only one when they named none.
    """
    clock = clock or SystemClock()
    try:
        # Revalidate even an internal model_construct/model_copy result before persisting it.
        content = BundleContent.model_validate_json(content.model_dump_json())
        if content.tenant_id != identity.tenant_id:
            raise PolicyStoreError("INVALID_BUNDLE")
        with db.transaction(identity.tenant_id) as conn:
            check_runtime(conn)
            _policy_identity(conn, identity, clock)
            selected = _creation_scope(conn, identity, content, space, source_bundle_id)
            _insert_draft(conn, identity, content, clock, selected)
            _policy_identity(conn, identity, clock)
            _creation_scope(conn, identity, content, selected, source_bundle_id)
        return BundleRecord(content, "DRAFT")
    except PolicyStoreError:
        raise
    except (SQLAlchemyError, ValueError):
        raise PolicyStoreError() from None


def change_draft_rules(
    db: Database,
    identity: Identity,
    bundle_id: UUID,
    ruleset: Ruleset,
    clock: Clock | None = None,
    *,
    catalog: Catalog = PRODUCTION_CATALOG,
) -> BundleRecord:
    """Rewrite a draft's rules as a successor draft, in one audited transaction.

    A person editing rules edits *a draft*, and the draft they end up with is the one this
    returns: the rules compiled through `ruleset_bundle`, so the components are the compiler's
    output by construction, inserted as a new DRAFT, with the draft it replaces retired in the
    same transaction. Nothing is rewritten, because nothing can be: the application role holds
    `SELECT, INSERT` on `policy_bundle_contents` and `UPDATE (state, changed_at)` on the
    lifecycle table, so a bundle's content and its digest are append-only in the database and
    not merely by convention (#273).

    What that buys is more than a workaround: every state the rules passed through stays in
    the tenant's own history as a retired draft, and `policy.rules_changed` names both ends of
    each step, so the chain says how a bundle came to say what it says. Only a DRAFT that
    already carries a ruleset may be changed; a validated one must be copied to a new draft,
    and a bundle written as a document has no rules to edit. Nothing here reaches ACTIVE
    without validation and activation recompiling and refusing a mismatch, exactly as before.
    """
    clock = clock or SystemClock()
    try:
        with db.transaction(identity.tenant_id) as conn:
            check_runtime(conn)
            _policy_identity(conn, identity, clock)
            _bundle_access(conn, identity, bundle_id, write=True)
            current = _read(conn, identity.tenant_id, bundle_id, lock=True)
            if current.state != "DRAFT" or current.content.ruleset is None:
                raise PolicyStoreError("INVALID_STATE")
            # A caller states the rules and the budgets; everything else the draft carries is
            # carried forward, so a surface that cannot express a field can never drop one.
            # The mappings decide which actions exist, and they are the draft's, not a
            # caller's, so a change of rules can never widen what the bundle reaches.
            ruleset = ruleset.model_copy(update={"context": current.content.ruleset.context})
            try:
                content = ruleset_bundle(
                    ruleset,
                    tenant_id=identity.tenant_id,
                    bundle_id=uuid4(),
                    mappings=current.content.mappings,
                    context_settings=current.content.context_settings,
                    signal_mappings=current.content.signal_mappings,
                    catalog=catalog,
                )
            except RulesetError as error:
                # The compiler's own field location, so a rule naming an undeclared fact or a
                # value outside its domain is refused where it was written.
                raise PolicyStoreError("INVALID_RULESET", location=error.location) from None
            content = BundleContent.model_validate_json(content.model_dump_json())
            _state(conn, current.content, "RETIRED", clock)
            _audit(conn, identity, current.content, "retired")
            _insert_draft(
                conn, identity, content, clock, _bundle_space(conn, identity.tenant_id, bundle_id)
            )
            append_event(
                conn,
                identity.tenant_id,
                identity.principal_id,
                "policy.rules_changed",
                {
                    "bundle_id": str(content.bundle_id),
                    "supersedes": str(current.content.bundle_id),
                    "content_hash": content.content_hash,
                    "rules": len(ruleset.rules),
                    "budgets": len(ruleset.budgets),
                    **acted_with(identity.credential_id),
                },
            )
            _policy_identity(conn, identity, clock)
        return BundleRecord(content, "DRAFT")
    except PolicyStoreError:
        raise
    except (SQLAlchemyError, ValueError):
        raise PolicyStoreError() from None


def validate_bundle(
    db: Database,
    identity: Identity,
    bundle_id: UUID,
    clock: Clock | None = None,
    *,
    catalog: Catalog = PRODUCTION_CATALOG,
) -> BundleRecord:
    """Reparse immutable DRAFT content and validate both Cedar sets and mappings."""
    clock = clock or SystemClock()
    try:
        with db.transaction(identity.tenant_id) as conn:
            check_runtime(conn)
            _policy_identity(conn, identity, clock)
            _bundle_access(conn, identity, bundle_id, write=True)
            bundle = _read(conn, identity.tenant_id, bundle_id, lock=True)
            if bundle.state != "DRAFT":
                raise PolicyStoreError("INVALID_STATE")
            _components(conn, bundle.content, catalog)
            _signal_mappings(conn, bundle.content, catalog, selecting=None)
            _ruleset(bundle.content, catalog)
            _state(conn, bundle.content, "VALIDATED", clock)
            _audit(conn, identity, bundle.content, "validated")
            _policy_identity(conn, identity, clock)
        return BundleRecord(bundle.content, "VALIDATED")
    except PolicyStoreError:
        raise
    except (SQLAlchemyError, ValueError):
        raise PolicyStoreError() from None


MAX_REASON = 500


def _activation_reason(reason: str | None) -> str | None:
    """A person's reason for an activation: stripped, 1 to 500 characters, and nothing the
    export's secret check would refuse (THREAT_MODEL.md T7.7). Named by its field, never
    quoted. None stays None, so a caller that gives none writes the payload it always did."""
    if reason is None:
        return None
    reason = reason.strip()
    if not 1 <= len(reason) <= MAX_REASON or secret_shaped(reason):
        raise PolicyStoreError("INVALID_REASON", location="reason")
    return reason


def activate_bundle(
    db: Database,
    identity: Identity,
    bundle_id: UUID,
    clock: Clock | None = None,
    *,
    catalog: Catalog = PRODUCTION_CATALOG,
    space: UUID | None = None,
    reason: str | None = None,
) -> BundleRecord:
    """Select one bundle for one space; deselect, select and audit atomically.

    **The fence does not move.** Activation still locks `tenant_policy_control` first and
    then writes the space's selection, so two activations in two spaces serialize on the
    same row they serialized on before spaces, admission reads the space's selection under
    the same lock it already takes, and there is no new lock order.

    `ACTIVE` means "selected by at least one space of this tenant". The previously selected
    bundle returns to `VALIDATED` only when no other space still selects it, so a baseline
    two customers share stays usable by the one that kept it.

    `reason`, a person's change note, is screened before anything is read and recorded on
    the activation event only (#678); the bundle and its content hash never carry it.
    """
    reason = _activation_reason(reason)
    clock = clock or SystemClock()
    try:
        with db.transaction(identity.tenant_id) as conn:
            check_runtime(conn)
            _policy_identity(conn, identity, clock)
            # Upsert first: a SELECT lock alone cannot serialize a missing control row.
            conn.execute(
                text("""
                INSERT INTO execbound.tenant_policy_control(tenant_id, changed_at)
                VALUES (:tenant, :now) ON CONFLICT (tenant_id) DO NOTHING
            """),
                {"tenant": identity.tenant_id, "now": _now(clock)},
            )
            conn.execute(
                text("""
                SELECT tenant_id FROM execbound.tenant_policy_control
                WHERE tenant_id = :tenant FOR UPDATE
            """),
                {"tenant": identity.tenant_id},
            ).scalar_one()
            selected = space or default_space(conn, identity.tenant_id)
            if not has_permission(
                conn, identity.tenant_id, identity.principal_id, "policy.manage", selected
            ):
                raise PolicyStoreError("INVALID_IDENTITY")
            active_id = _selected_in(conn, identity.tenant_id, selected)
            # Waiting for another activation must not preserve stale administrator validity.
            _policy_identity(conn, identity, clock)
            _bundle_access(conn, identity, bundle_id, write=False)
            bundle = _read(conn, identity.tenant_id, bundle_id, lock=True)
            if bundle.state not in {"VALIDATED", "ACTIVE"}:
                raise PolicyStoreError("INVALID_STATE")
            if bundle.state == "ACTIVE" and active_id == bundle_id:
                raise PolicyStoreError("INVALID_STATE")
            _components(conn, bundle.content, catalog)
            _signal_mappings(conn, bundle.content, catalog, selecting=selected)
            _ruleset(bundle.content, catalog)
            _state(conn, bundle.content, "ACTIVE", clock)
            _select(conn, identity, selected, bundle_id, clock)
            if active_id is not None and active_id != bundle_id:
                prior = _read(conn, identity.tenant_id, active_id, lock=True)
                if prior.state != "ACTIVE":
                    raise PolicyStoreError("INVALID_STATE")
                if not _selected_anywhere(conn, identity.tenant_id, active_id):
                    _state(conn, prior.content, "VALIDATED", clock)
                    _audit(conn, identity, prior.content, "deselected", space=selected)
            _audit(conn, identity, bundle.content, "activated", space=selected, reason=reason)
            _policy_identity(conn, identity, clock)
        return BundleRecord(bundle.content, "ACTIVE")
    except PolicyStoreError:
        raise
    except (SQLAlchemyError, ValueError):
        raise PolicyStoreError() from None


def activate_new_bundle(
    conn: Connection,
    identity: Identity,
    content: BundleContent,
    clock: Clock,
    *,
    space: UUID,
    catalog: Catalog = PRODUCTION_CATALOG,
) -> BundleRecord:
    """Create, validate and activate one new bundle inside the caller's fenced transaction.

    For a caller that must make a bundle live in the same transaction as the registry rows its
    mappings name, which is sample targets (#420): those rows exist only inside that
    transaction, so `create_bundle`, `validate_bundle` and `activate_bundle`, each its own
    transaction, could not see them. The checks are theirs, in their order, with their audit
    events: the creation scope, the components against the tenant's current registry, the
    ruleset recompiled and compared, then the selection. It refuses a space that already
    selects a bundle, so it never replaces anything a person chose.
    """
    content = BundleContent.model_validate_json(content.model_dump_json())
    if content.tenant_id != identity.tenant_id:
        raise PolicyStoreError("INVALID_BUNDLE")
    _policy_identity(conn, identity, clock)
    selected = _creation_scope(conn, identity, content, space, None)
    if _selected_in(conn, identity.tenant_id, selected) is not None:
        raise PolicyStoreError("INVALID_STATE")
    _insert_draft(conn, identity, content, clock, selected)
    _components(conn, content, catalog)
    _signal_mappings(conn, content, catalog, selecting=selected)
    _ruleset(content, catalog)
    _state(conn, content, "VALIDATED", clock)
    _audit(conn, identity, content, "validated")
    _state(conn, content, "ACTIVE", clock)
    _select(conn, identity, selected, content.bundle_id, clock)
    _audit(conn, identity, content, "activated", space=selected)
    _policy_identity(conn, identity, clock)
    return BundleRecord(content, "ACTIVE")


def retire_bundle(
    db: Database,
    identity: Identity,
    bundle_id: UUID,
    clock: Clock | None = None,
) -> BundleRecord:
    """Retire a bundle that no space selects, from any state but `RETIRED`.

    A bundle a space selects is refused as `INVALID_STATE`, so retiring never leaves a space
    without a selection: activate a replacement first, which returns this bundle to
    `VALIDATED` once no other space selects it.
    """
    clock = clock or SystemClock()
    try:
        with db.transaction(identity.tenant_id) as conn:
            check_runtime(conn)
            _policy_identity(conn, identity, clock)
            conn.execute(
                text("""
                INSERT INTO execbound.tenant_policy_control(tenant_id, changed_at)
                VALUES (:tenant, :now) ON CONFLICT (tenant_id) DO NOTHING
            """),
                {"tenant": identity.tenant_id, "now": _now(clock)},
            )
            conn.execute(
                text("""
                SELECT tenant_id FROM execbound.tenant_policy_control
                WHERE tenant_id = :tenant FOR UPDATE
            """),
                {"tenant": identity.tenant_id},
            ).scalar_one()
            _policy_identity(conn, identity, clock)
            _bundle_access(conn, identity, bundle_id, write=True)
            bundle = _read(conn, identity.tenant_id, bundle_id, lock=True)
            if bundle.state == "RETIRED":
                raise PolicyStoreError("INVALID_STATE")
            if _selected_anywhere(conn, identity.tenant_id, bundle_id):
                # A bundle a space selects cannot be retired: retiring it would change
                # that space's admission from under it, and with several spaces the
                # administrator retiring it may not be able to see them all.
                raise PolicyStoreError("INVALID_STATE")
            _state(conn, bundle.content, "RETIRED", clock)
            _audit(conn, identity, bundle.content, "retired")
            _policy_identity(conn, identity, clock)
        return BundleRecord(bundle.content, "RETIRED")
    except PolicyStoreError:
        raise
    except (SQLAlchemyError, ValueError):
        raise PolicyStoreError() from None


def list_bundles(
    db: Database, identity: Identity, clock: Clock | None = None, *, space: UUID | None = None
) -> tuple[BundleSummary, ...]:
    """A current ADMIN's view of every bundle's lifecycle state, newest change first.

    ``active`` is "selected by the space the reader is looking at", or by any space when
    they are looking at all of theirs, which is what `ACTIVE` means since spaces.
    """
    clock = clock or SystemClock()
    try:
        with db.transaction(identity.tenant_id, snapshot=True) as conn:
            check_runtime(conn)
            _policy_identity(conn, identity, clock)
            rows = (
                conn.execute(
                    text("""
                    SELECT s.bundle_id, s.content_hash, s.state, s.changed_at,
                           EXISTS (SELECT 1 FROM execbound.space_policy_selection p
                                    WHERE p.tenant_id = s.tenant_id
                                      AND p.bundle_id = s.bundle_id
                                      AND (CAST(:space AS uuid) IS NULL
                                           OR p.space_id = :space)) AS active
                    FROM execbound.policy_bundle_lifecycle s
                    WHERE s.tenant_id = :tenant AND EXISTS (
                        SELECT 1 FROM execbound.policy_bundle_contents c
                        WHERE c.tenant_id=s.tenant_id AND c.bundle_id=s.bundle_id
                        AND (c.offered_tenant_wide OR execbound.access_has_permission(
                            :principal,'policy.manage',c.space_id,false)))
                    ORDER BY s.changed_at DESC, s.bundle_id
                """),
                    {
                        "tenant": identity.tenant_id,
                        "space": space,
                        "principal": identity.principal_id,
                    },
                )
                .mappings()
                .all()
            )
            _policy_identity(conn, identity, clock)
        return tuple(
            BundleSummary(
                row["bundle_id"],
                row["content_hash"],
                row["state"],
                row["changed_at"],
                row["active"] is True,
            )
            for row in rows
        )
    except PolicyStoreError:
        raise
    except (SQLAlchemyError, ValueError):
        raise PolicyStoreError() from None


def read_bundle(
    db: Database, identity: Identity, bundle_id: UUID, clock: Clock | None = None
) -> BundleRecord:
    """A current ADMIN's snapshot read of one bundle's content and lifecycle state."""
    clock = clock or SystemClock()
    try:
        with db.transaction(identity.tenant_id, snapshot=True) as conn:
            check_runtime(conn)
            _policy_identity(conn, identity, clock)
            _bundle_access(conn, identity, bundle_id, write=False)
            record = _read(conn, identity.tenant_id, bundle_id, lock=False)
            _policy_identity(conn, identity, clock)
        return record
    except PolicyStoreError:
        raise
    except (SQLAlchemyError, ValueError):
        raise PolicyStoreError() from None


def load_active_bundle(
    db: Database,
    identity: Identity,
    clock: Clock | None = None,
    *,
    catalog: Catalog = PRODUCTION_CATALOG,
    space: UUID | None = None,
) -> BundleContent:
    """Load a digest-checked selected snapshot; later execution must recheck selection.

    The selection is the **space's** since migration 0041; a caller that names none reads
    the tenant's only space, which is every tenant that never made a second.
    """
    clock = clock or SystemClock()
    try:
        with db.transaction(identity.tenant_id, snapshot=True) as conn:
            check_runtime(conn)
            _identity(conn, identity, clock, admin=False)
            active_id = conn.execute(
                text("""
                SELECT bundle_id FROM execbound.space_policy_selection
                WHERE tenant_id = :tenant AND space_id = :space
            """),
                {
                    "tenant": identity.tenant_id,
                    "space": space or default_space(conn, identity.tenant_id),
                },
            ).scalar_one_or_none()
            if active_id is None:
                # A space with no selection fails closed exactly as a tenant with none did.
                raise PolicyStoreError("NO_ACTIVE_BUNDLE")
            bundle = _read(conn, identity.tenant_id, active_id, lock=False)
            if bundle.state != "ACTIVE":
                raise PolicyStoreError("INVALID_STATE")
            _components(conn, bundle.content, catalog)
            _identity(conn, identity, clock, admin=False)
        return bundle.content
    except PolicyStoreError:
        raise
    except (SQLAlchemyError, ValueError):
        raise PolicyStoreError() from None
