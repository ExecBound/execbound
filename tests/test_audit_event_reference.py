# SPDX-License-Identifier: AGPL-3.0-only
"""The audit event reference names every kind the chain can carry, and the fields of each.

`docs/AUDIT_EVENTS.md` is written by hand, because what a kind means is not in the code. These
tests hold it to the code instead. Every kind replay knows has one row there, except the kinds
only a first-party plugin writes, which are documented with the plugin and checked by the
plugin's own test. Every other kind a module writes under its own name has a row, whether or
not replay knows it, and every payload field such a writer names is in its kind's row. The
other way round, every field a row names is written by some writer of its kind, unless a
reviewed list here says why the scan cannot see the writer name it.
"""

import ast
import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from execbound.replay import verify
from execbound.replay.models import DecisionCapture

# Reads a document, so it carries `docs` and `pytest -m docs` selects it (#748).
pytestmark = pytest.mark.docs

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "docs" / "AUDIT_EVENTS.md"
SOURCES = ROOT / "src"

# The kinds `_verified_events` gives semantics by name, beside the informational ones.
DECIDING = frozenset(
    {"execution.evaluated", "execution.transition", "approval.transition", *verify._STOP_EVENTS}
)

# Kinds replay knows that only a first-party plugin writes: its plan, signup and onboarding
# lifecycle. They are documented with the plugin, never on a published page, and the
# plugin's own test holds this list to the plugin's code.
PLUGIN_KINDS = frozenset(
    {
        "account.preferences",
        # A hosted password reset from an emailed link (#678).
        "account_security.password_reset",
        "agents.slept",
        "agents.woken",
        "sandbox.adopted",
        "sandbox.invitation_resent",
        "sandbox.invitation_revoked",
        "sandbox.invited",
        "sandbox.seeded",
        "tenant.claimed",
        "tenant.converted",
        "tenant.deactivated",
        "tenant.expired",
        "tenant.extended",
        "tenant.fell_back",
        "tenant.provisioned",
    }
)

_KIND = re.compile(r"[a-z][a-z0-9_]*\.[a-z0-9_.]+")
_ROW = re.compile(r"^\| `([a-z][a-z0-9_]*\.[a-z0-9_.]+)` \| .+? \| (.+?) \|$")


def reference_rows(path: Path) -> dict[str, frozenset[str]]:
    """Each catalogue row of a reference page: its kind, and the fields its last cell names."""
    rows: dict[str, frozenset[str]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = _ROW.match(line)
        if match is None:
            continue
        kind, fields = match.groups()
        assert kind not in rows, f"{path.name}: {kind} has two rows"
        rows[kind] = frozenset(re.findall(r"`([a-z_]+)`", fields))
    return rows


@dataclass(frozen=True)
class Write:
    """One `append_event` call: where it is, the kinds it can name, and its payload's fields.

    `kinds` is empty when the kind is built at run time, which replay's own list covers;
    `prefix` is then the literal it starts with, when it starts with one.
    `fields` is a floor: a payload spread from something these tests cannot read has more.
    """

    where: str
    kinds: tuple[str, ...]
    fields: frozenset[str]
    prefix: str = ""


def _string_constants(trees: dict[Path, ast.Module]) -> dict[str, str]:
    """Module-level names bound to a kind-shaped string, wherever they are defined.

    A name bound to two different kinds in two modules is left out, so it stays unresolved
    rather than resolving to the wrong one."""
    found: dict[str, set[str]] = {}
    for tree in trees.values():
        for node in tree.body:
            if (
                isinstance(node, ast.Assign)
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)
                and _KIND.fullmatch(node.value.value)
            ):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        found.setdefault(target.id, set()).add(node.value.value)
    return {name: next(iter(values)) for name, values in found.items() if len(values) == 1}


def named_kinds(node: ast.expr, constants: dict[str, str]) -> tuple[str, ...]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return (node.value,)
    if isinstance(node, ast.IfExp):
        body, orelse = named_kinds(node.body, constants), named_kinds(node.orelse, constants)
        return body + orelse if body and orelse else ()
    if isinstance(node, ast.Name) and node.id in constants:
        return (constants[node.id],)
    return ()


def kind_prefix(node: ast.expr) -> str:
    """The literal a kind built at run time starts with: `"access." + operation` or
    `f"identity_provider.{state}"`; empty when it starts with none."""
    if (
        isinstance(node, ast.BinOp)
        and isinstance(node.op, ast.Add)
        and isinstance(node.left, ast.Constant)
        and isinstance(node.left.value, str)
    ):
        return node.left.value
    if (
        isinstance(node, ast.JoinedStr)
        and node.values
        and isinstance(node.values[0], ast.Constant)
        and isinstance(node.values[0].value, str)
    ):
        return node.values[0].value
    return ""


def _bound(name: str, scope: ast.AST | None, seen: frozenset[str]) -> frozenset[str]:
    """The fields a payload held in a local name is given in its function: each dict bound to
    the name there, and each key a literal subscript assigns into it."""
    if scope is None or name in seen:
        return frozenset()
    fields: set[str] = set()
    for node in ast.walk(scope):
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets, value = [node.target], node.value
        else:
            continue
        for target in targets:
            if isinstance(target, ast.Name) and target.id == name:
                fields |= payload_fields(value, scope, seen | {name})
            elif (
                isinstance(target, ast.Subscript)
                and isinstance(target.value, ast.Name)
                and target.value.id == name
                and isinstance(target.slice, ast.Constant)
                and isinstance(target.slice.value, str)
            ):
                fields.add(target.slice.value)
    return frozenset(fields)


def _spread(
    node: ast.expr, scope: ast.AST | None = None, seen: frozenset[str] = frozenset()
) -> frozenset[str]:
    """The fields a `**spread` inside a payload adds, where they can be read."""
    if isinstance(node, ast.Name):
        return _bound(node.id, scope, seen)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        if node.func.id == "acted_with":
            return frozenset({"actor_credential_id"})
        if (
            node.func.id == "withheld"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            field = node.args[0].value
            return frozenset({field, f"{field}_digest"})
    if isinstance(node, ast.Dict):
        return payload_fields(node, scope, seen)
    if isinstance(node, ast.IfExp):
        return _spread(node.body, scope, seen) | _spread(node.orelse, scope, seen)
    return frozenset()


def payload_fields(
    node: ast.expr, scope: ast.AST | None = None, seen: frozenset[str] = frozenset()
) -> frozenset[str]:
    """The fields a payload expression names where they can be read.

    Given the function the payload is built in, a payload held in a local name, or spread
    from one, is read through what that function binds to the name."""
    if isinstance(node, ast.Name):
        return _bound(node.id, scope, seen)
    if not isinstance(node, ast.Dict):
        return frozenset()
    fields: set[str] = set()
    for key, value in zip(node.keys, node.values, strict=True):
        if key is None:
            fields |= _spread(value, scope, seen)
        elif isinstance(key, ast.Constant) and isinstance(key.value, str):
            fields.add(key.value)
    return frozenset(fields)


def parse_sources(root: Path) -> dict[Path, ast.Module]:
    paths = sorted(root.rglob("*.py"))
    return {path: ast.parse(path.read_text(encoding="utf-8")) for path in paths}


def append_event_calls(tree: ast.AST) -> Iterator[ast.Call]:
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            function = node.func
            name = function.attr if isinstance(function, ast.Attribute) else None
            name = function.id if isinstance(function, ast.Name) else name
            if name == "append_event" and len(node.args) >= 5:
                yield node


def _functions(tree: ast.Module) -> dict[int, ast.AST]:
    """Each `append_event` call's innermost enclosing function, by the call's identity."""
    found: dict[int, ast.AST] = {}
    # `ast.walk` is breadth first, so an inner function is reached after the one around it.
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for call in append_event_calls(node):
                found[id(call)] = node
    return found


def module_writes() -> list[Write]:
    """Every `append_event` call in the source tree."""
    trees = parse_sources(SOURCES)
    constants = _string_constants(trees)
    writes = []
    for path, tree in trees.items():
        functions = _functions(tree)
        for call in append_event_calls(tree):
            kinds = named_kinds(call.args[3], constants)
            writes.append(
                Write(
                    where=f"{path.relative_to(ROOT)}:{call.lineno}",
                    kinds=kinds,
                    fields=payload_fields(call.args[4], functions.get(id(call))),
                    prefix="" if kinds else kind_prefix(call.args[3]),
                )
            )
    return writes


# The first-party plugin's sources, which the self-hosted export leaves out. Only core's
# writers count when a row's fields are read back to them, so the check finds the same in
# this repository and in the export, where fewer writers could only hide a field.
PLUGIN_SOURCES = "src/execbound/hosted/"

# Held to `DecisionCapture` exactly, both ways, by its own test below.
CAPTURED = "execution.evaluated"

# Fields a row names that no writer the scan reads is seen to write, each reviewed by hand.
# The scan reads a payload written as a literal, held in a local name or spread from one, and
# a kind named outright or built from a literal prefix; these reach `append_event` another way.
# An entry the scan can now see, or one its row no longer names, fails the reverse test, so
# the list can only shrink.
UNREAD_FIELDS: dict[str, frozenset[str]] = {
    # `mfa._event` spreads the `data` its callers pass it, in `mfa`, `passkeys` and
    # `account_links`.
    "account_security.provider_link_started": frozenset({"provider"}),
    "account_security.provider_linked": frozenset({"provider"}),
    "account_security.recovery_used": frozenset({"method"}),
    "account_security.requirement_changed": frozenset({"requirement"}),
    "account_security.verification_failed": frozenset({"method"}),
    "account_security.verified": frozenset({"method"}),
    # `assistant.loop._audit` appends the kind and payload its callers pass it.
    "assistant.asked": frozenset({"cannot_answer"}),
    "assistant.refused": frozenset({"turn_id", "reason", "tools", "actor_credential_id"}),
    # `provisioning.import_manifest` spreads the import's `writes.counts`.
    "context.imported": frozenset(
        {
            "applied",
            "entries",
            "facts_retracted",
            "facts_written",
            "incidents_created",
            "incidents_updated",
            "resources_deactivated",
            "unchanged",
            "unknown_resources",
        }
    ),
    # `arcade.store` appends the payload its caller builds.
    "execution.control_point_contradiction": frozenset(
        {
            "contradiction",
            "tool_identity",
            "toolkit",
            "tool_name",
            "tool_version",
            "execution_id",
            "operation_id",
            "plan_hash",
        }
    ),
    # A transition's caller passes its own detail in the payload `execution.store.event` extends.
    "execution.transition": frozenset({"reason"}),
    # `passwords` spreads the `detail` its caller passes, `withheld("subject", ...)`.
    "human_sign_in.github": frozenset({"subject", "subject_digest"}),
    "human_sign_in.google": frozenset({"subject", "subject_digest"}),
    "human_sign_in.microsoft": frozenset({"subject", "subject_digest"}),
    # `access_control` appends it from a loop over the kinds a role promotion revokes.
    "identity.invitation_revoked": frozenset({"reason"}),
    # `personal_tokens._change` appends the kind its callers pass it.
    "personal_token.deleted": frozenset({"token_id", "actor_credential_id"}),
    "personal_token.revoked": frozenset({"token_id", "actor_credential_id"}),
    # `execution.stops._payload` builds both.
    "tenant.stop_activated": frozenset(
        {"stop_id", "reason", "principal_id", "credential_id", "actor_credential_id", "replay"}
    ),
    "tenant.stop_released": frozenset(
        {"stop_id", "reason", "principal_id", "credential_id", "actor_credential_id", "replay"}
    ),
}


def written_fields(kind: str, writes: list[Write]) -> frozenset[str]:
    """Every field a writer that can append `kind` is seen to name, one built from a prefix
    of it included."""
    return frozenset().union(
        *(
            write.fields
            for write in writes
            if kind in write.kinds or (write.prefix and kind.startswith(write.prefix))
        )
    )


def test_every_kind_replay_knows_has_one_row_unless_only_a_plugin_writes_it() -> None:
    known = verify._INFORMATIONAL | DECIDING
    rows = reference_rows(REFERENCE)
    assert PLUGIN_KINDS <= known, sorted(PLUGIN_KINDS - known)
    stale = set(rows) - known
    assert not stale, f"rows for kinds replay does not know: {sorted(stale)}"
    missing = known - PLUGIN_KINDS - set(rows)
    assert not missing, f"kinds replay knows with no row in {REFERENCE.name}: {sorted(missing)}"
    assert not PLUGIN_KINDS & set(rows), sorted(PLUGIN_KINDS & set(rows))


def test_every_kind_a_module_writes_by_name_has_a_row() -> None:
    writes = module_writes()
    named = [write for write in writes if write.kinds]
    # The scan reads the calls it should: almost every write names its kind.
    assert len(named) > 0.8 * len(writes) > 80
    rows = reference_rows(REFERENCE)
    missing = sorted(
        f"{kind} ({write.where})"
        for write in named
        for kind in write.kinds
        if kind not in rows and kind not in PLUGIN_KINDS
    )
    assert not missing, f"kinds written with no row in {REFERENCE.name}: {missing}"


def test_each_row_names_every_field_its_writers_name() -> None:
    rows = reference_rows(REFERENCE)
    missing = sorted(
        f"{kind}.{field} ({write.where})"
        for write in module_writes()
        for kind in write.kinds
        if kind not in PLUGIN_KINDS
        for field in write.fields - rows.get(kind, frozenset())
    )
    assert not missing, f"payload fields missing from {REFERENCE.name}: {missing}"


def test_the_decision_capture_row_names_exactly_the_capture_s_fields() -> None:
    assert reference_rows(REFERENCE)["execution.evaluated"] == set(DecisionCapture.model_fields)


def test_each_field_a_row_names_is_written_by_a_writer_of_its_kind() -> None:
    rows = reference_rows(REFERENCE)
    writes = [write for write in module_writes() if not write.where.startswith(PLUGIN_SOURCES)]
    written = {kind: written_fields(kind, writes) for kind in rows}
    stale = sorted(
        f"{kind}.{field}"
        for kind, fields in rows.items()
        if kind != CAPTURED
        for field in fields - written[kind] - UNREAD_FIELDS.get(kind, frozenset())
    )
    assert not stale, f"fields {REFERENCE.name} names that no writer of the kind writes: {stale}"
    # The reviewed list holds only what the scan still cannot see and the rows still name.
    outdated = sorted(
        f"{kind}.{field}"
        for kind, fields in UNREAD_FIELDS.items()
        for field in fields
        if field not in rows.get(kind, frozenset()) or field in written.get(kind, frozenset())
    )
    assert not outdated, f"UNREAD_FIELDS entries to remove: {outdated}"
