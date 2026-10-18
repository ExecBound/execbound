# SPDX-License-Identifier: AGPL-3.0-only
"""What a regression fixture replaces with typed pseudonyms, and what a sanitized one holds.

The sanitizer collects these values from an export and replaces them (`sanitize.py`); the
fixture reader refuses a fixture that still holds one, or holds any identifier that is not a
pseudonym (`fixture.py`). Both read the same positions here, so a fixture written by hand or
re-recorded from one is held to what a build would have written.

A label is replaced at the position it was recorded at. The sanitizer also replaces it, and
looks for it, wherever else it appears, unless its text is a word the fixture keeps anyway:
a field name or a value at a field the catalog or the kernel fills from a closed vocabulary
(`vocabulary`), or a word every fixture may hold whatever history it came from: the
catalog's, the Cedar language's, the kernel's own transition reasons, and the fixed text of a
case link's pseudonym (`PUBLIC_WORDS`). Such a word is left where the kernel wrote it, so an
owner's ref named after the vendor's own operation, or a comment that reads `approved` or
`permit`, neither rewrites the history nor stops it becoming a fixture.
"""

import copy
import json
import re
from collections.abc import Callable, Iterable, Iterator, Mapping
from typing import Any

from execbound.contracts import (
    PRODUCTION_CATALOG,
    SIGNAL_WRITER,
    ContractError,
    StringDomain,
)

# The order a value takes its type in when it is found in more than one place.
LABEL_TYPES = (
    "host",
    "resource",
    "object",
    "event",
    "key",
    "reference",
    "case",
    "source",
    "url",
    "writer",
    "operation",
    "version",
    "value",
    "reason",
    "comment",
    "note",
)
# Types replaced, and looked for, only where they are a whole value or a whole string inside
# embedded JSON such as a journal record, when they hold no letter (`_whole_only`). A version
# is often a bare number, such as `7`, whose digits are also tokens of every time a history
# holds. One with a letter, such as `acme-map-7`, names something as a host does, and is
# replaced and looked for as a whole token like any other label. An operation ref the catalog
# spells inside its own names (`isolate` in `endpoint.isolate`) is a kept word and is not
# looked for at all.
EXACT_TYPES = frozenset({"operation", "version"})
# The reasons the kernel itself writes on an execution transition. Every other reason is text
# a person typed, such as a reconciliation's, and is replaced however it is shaped: a change
# number like `CHG0031337` reads as a code but is not one.
REASON_CODES = frozenset(
    {
        "APPROVAL_EXPIRED",
        "CHANGED_OBLIGATIONS",
        "EXECUTOR_REPORT",
        "HUMAN_DENIED",
        "INCONCLUSIVE_JOURNAL",
        "INVALID_APPROVAL",
        "PROVIDER_RESPONSE",
        "RESOURCE_BUSY",
        "STALE_AUTHORIZATION",
        "UNREPORTED_GRANT",
    }
)
# What a whole token is made of. A token label is replaced, and looked for, only where neither
# side continues it, so `device-01` inside `tenant-total-device-01` is a rule id, not a host.
WORD = "A-Za-z0-9_-"
# Fields whose strings the catalog or the kernel fills from a closed vocabulary, or that a
# fixture keeps by design: rule ids, a signal's producer and a request's number. No label is
# collected from a field of these names; `_vocabulary_field` adds the few that need a parent.
VOCABULARY_FIELDS = frozenset(
    {
        "action",
        "actions",
        "budget",
        "capability",
        "combination",
        "context_contract_version",
        "decision",
        "dependencies",
        "effect",
        "fact",
        "from_state",
        "human_decision",
        "id",
        "kind",
        "minimum_correlation",
        "mode",
        "name",
        "obligation",
        "obligation_ids",
        "obligations",
        "on_exceed",
        "operator",
        "origin",
        "outcome",
        "precondition_class",
        "principalTypes",
        "producer_name",
        "producer_version",
        "provenance",
        "provider",
        "provider_operation",
        "reasons",
        "recorded_effect",
        "request_ref",
        "resourceTypes",
        "resource_type",
        "rule_id",
        "schema_version",
        "scope",
        "settlement_tier",
        "source_kind",
        "stage",
        "status",
        "to_state",
        "type",
        "verdict",
    }
)
# The Cedar language's own words, which a policy's text spells beside the catalog's names.
_CEDAR_WORDS = frozenset(
    {
        "Action",
        "context",
        "else",
        "false",
        "forbid",
        "has",
        "if",
        "in",
        "is",
        "like",
        "permit",
        "principal",
        "resource",
        "then",
        "true",
        "unless",
        "when",
    }
)
_TOKEN = re.compile(f"[{WORD}]+")


def _tokens(words: Iterable[str]) -> frozenset[str]:
    """Each word and every whole token in it, so `isolate` is a word as `endpoint.isolate` is."""
    found = set(words)
    return frozenset(found | {token for word in found for token in _TOKEN.findall(word)})


def _domain(domain: object) -> frozenset[str]:
    return frozenset(domain.values) if isinstance(domain, StringDomain) else frozenset()


def _catalog() -> tuple[frozenset[str], frozenset[str]]:
    """Every word the production catalog and its contracts define, and its own writers."""
    actions = PRODUCTION_CATALOG.actions
    words = set(actions.names)
    writers = {SIGNAL_WRITER}
    for spec in actions.specs:
        words |= {spec.resource_type, spec.context_contract_version}
        for argument in spec.arguments:
            words |= {argument.name, *_domain(argument.domain)}
    for binding in actions.bindings:
        words |= {binding.provider, binding.provider_operation, binding.schema_version}
    for version in PRODUCTION_CATALOG.versions:
        contract = PRODUCTION_CATALOG.contract(version)
        words |= {version, contract.resource_type, contract.cedar_entity_type}
        words.add(contract.display_fact)
        for kind, defaults in contract.sources.items():
            words.add(kind)
            writers |= set(defaults.permitted_writers)
        for fact in contract.facts:
            words |= {fact.name, fact.source_kind, *_domain(fact.domain)}
    return frozenset(words | writers), frozenset(writers)


_CATALOG_WORDS, CATALOG_WRITERS = _catalog()
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_EVERY_UUID = re.compile(r"(?=([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}))")
_IDENTIFIER = re.compile(r"00000000-0000-4000-8000-[0-9a-f]{12}")
_URL = "https://case.invalid/url-"
# Words every fixture may hold whatever history it came from: the catalog's, the kernel's
# reason codes, Cedar's, and the fixed text of a case link's pseudonym (`https`, `case` and
# `invalid`), which a fixture writes where a source held a link.
PUBLIC_WORDS = _tokens(_CATALOG_WORDS | REASON_CODES | _CEDAR_WORDS | {_URL})
_PSEUDONYM = re.compile(
    "(?:(?:" + "|".join(LABEL_TYPES) + ")-[0-9]{6,}|" + re.escape(_URL) + "[0-9]{6,})"
)
# A request with a reference carries the key derived from it (`requests.derive_key`), which is
# derived again from the reference's pseudonym.
_DERIVED_KEY = re.compile(_PSEUDONYM.pattern + "-[0-9a-f]{32}")


def identifier(rank: int) -> str:
    """Rank *n* of the source's identifiers, sorted by their original text."""
    return f"00000000-0000-4000-8000-{rank:012x}"


def pseudonym(kind: str, rank: int) -> str:
    """Rank *n* of one type's labels, sorted by their original text."""
    if kind == "url":
        return f"{_URL}{rank:06d}"
    return f"{kind}-{rank:06d}"


def _identifier_like(value: str) -> bool:
    return bool(
        _UUID.fullmatch(value.lower())
        or re.fullmatch(r"[0-9A-Fa-f]{32}", value)
        or re.fullmatch(r"[0-9A-Fa-f]{64}", value)
    )


def _closed(plan: Mapping[str, Any], fact: Mapping[str, Any]) -> bool:
    """Whether a string fact's value is vocabulary: inside its contract's closed domain."""
    try:
        spec = PRODUCTION_CATALOG.contract(plan["context_contract_version"]).fact(fact["name"])
    except (ContractError, KeyError, TypeError):
        return False
    return isinstance(spec.domain, StringDomain) and fact.get("value") in spec.domain.values


Visit = Callable[[Any, Any, str], None]
"""Called with a container, the key or index of a label position in it, and its type."""


def _value(container: Any, key: Any) -> Any:
    if isinstance(container, Mapping):
        return container.get(key)
    if isinstance(container, list) and isinstance(key, int) and 0 <= key < len(container):
        return container[key]
    return None


def _operation(container: Any, visit: Visit) -> None:
    """An operation ref an owner named; a catalog action's own name is vocabulary."""
    if _value(container, "operation_ref") not in PRODUCTION_CATALOG.actions.names:
        visit(container, "operation_ref", "operation")


def _case(case: Any, visit: Visit) -> None:
    if isinstance(case, Mapping):
        visit(case, "source", "source")
        visit(case, "case_id", "case")
        visit(case, "url", "url")


def _writers(container: Any, visit: Visit) -> None:
    """The context writers an owner named, which its bundle's context settings permit. The
    catalog's own writers, such as `soc_analyst`, are vocabulary."""
    writers = _value(container, "permitted_writers")
    if isinstance(writers, list):
        for index, writer in enumerate(writers):
            if writer not in CATALOG_WRITERS:
                visit(writers, index, "writer")


def _plan(plan: Mapping[str, Any], visit: Visit) -> None:
    visit(plan, "resource_provider_id", "resource")
    visit(plan, "resource_version", "version")
    visit(plan, "mapping_version", "version")
    request = plan.get("request")
    if isinstance(request, Mapping):
        _operation(request, visit)
        target = request.get("target")
        if isinstance(target, Mapping) and target.get("kind") in {"hostname", "provider_id"}:
            visit(target, "value", "host")
        visit(request, "idempotency_key", "key")
        visit(request, "reference", "reference")
        _case(request.get("external_case"), visit)
    for fact in plan.get("facts") or ():
        if not isinstance(fact, Mapping):
            continue
        visit(fact, "source_object_id", "object")
        if isinstance(fact.get("value"), str) and not _closed(plan, fact):
            visit(fact, "value", "value")
        # A fact's source version is the version its inventory row, fact row or incident
        # recorded, as the owner's writer supplied it (`resolution/facts.py`). A signal fact's
        # is its source's registration number, which evaluation compares with the number its
        # records carry, so it is kept.
        if fact.get("source_kind") != "signal":
            visit(fact, "source_version", "version")
        _writers(fact, visit)
        signal = fact.get("signal")
        if isinstance(signal, Mapping):
            for record in signal.get("records") or ():
                if isinstance(record, Mapping):
                    visit(record, "source_event_id", "event")


def _bundle(bundle: Any, visit: Visit) -> None:
    if not isinstance(bundle, Mapping):
        return
    for mapping in bundle.get("mappings") or ():
        if isinstance(mapping, Mapping):
            _operation(mapping, visit)
            visit(mapping, "mapping_version", "version")
    settings = list(bundle.get("context_settings") or ())
    ruleset = bundle.get("ruleset")
    if isinstance(ruleset, Mapping):
        for rule in ruleset.get("rules") or ():
            if isinstance(rule, Mapping):
                visit(rule, "note", "note")
        settings += ruleset.get("context") or ()
    for setting in settings:
        _writers(setting, visit)


def _journal(payload: Mapping[str, Any], visit: Visit) -> None:
    """A settlement's provider journal, whose command copies the plan's resource and version
    and whose record carries the version the provider reported. It is embedded JSON, read as
    text or, while `rewrite` replaces labels, already parsed."""
    evidence = payload.get("evidence")
    if not isinstance(evidence, Mapping):
        return
    signed: Any = evidence.get("authenticated_record")
    try:
        if isinstance(signed, str):
            signed = json.loads(signed)
        record = signed["record"]
        command = record["command"]
    except (KeyError, TypeError, ValueError, RecursionError):
        return
    if not isinstance(record, dict) or not isinstance(command, dict):
        return
    visit(command, "resource_provider_id", "resource")
    visit(command, "expected_version", "version")
    visit(record, "resulting_version", "version")


def _transition(payload: Mapping[str, Any], visit: Visit) -> None:
    if payload.get("reason") not in REASON_CODES:
        visit(payload, "reason", "reason")
    # Admission writes the request's operation ref and the agent's case at the top of an
    # execution's first transition (`execution/store.py` `event`): the frozen plan beside
    # them carries no request, so this is the one place the case reaches an export.
    _operation(payload, visit)
    _case(payload.get("external_case"), visit)
    _journal(payload, visit)


def positions(document: Mapping[str, Any], visit: Visit) -> None:
    """Visit every position the kept structure of an export and its candidates holds a label
    at. `document` holds `export` and `candidates`, as a fixture does."""
    for bundle in (*document["export"]["bundles"], *document["candidates"]):
        _bundle(bundle, visit)
    for event in document["export"]["events"]:
        kind, payload = event["kind"], event["payload"]
        if not isinstance(payload, Mapping):
            continue
        if isinstance(payload.get("frozen"), Mapping):
            _plan(payload["frozen"], visit)
        if kind in {"tenant.stop_activated", "tenant.stop_released"}:
            visit(payload, "reason", "reason")
        if kind == "execution.transition":
            _transition(payload, visit)
        if kind == "approval.transition":
            visit(payload, "comment", "comment")


def _label(value: Any) -> bool:
    return isinstance(value, str) and bool(value) and not _identifier_like(value)


def collect(document: Mapping[str, Any]) -> dict[str, str]:
    """Every label the kept structure of an export and its candidates carries, with its type."""
    found: dict[str, set[str]] = {}

    def visit(container: Any, key: Any, kind: str) -> None:
        value = _value(container, key)
        if _label(value):
            found.setdefault(value, set()).add(kind)

    positions(document, visit)
    return {
        value: next(kind for kind in LABEL_TYPES if kind in kinds) for value, kinds in found.items()
    }


class _Journal(dict[str, Any]):
    """A settlement's journal, parsed while `rewrite` runs and written back as JSON after."""


def _opened(document: Mapping[str, Any]) -> dict[str, Any]:
    """A copy of `document` whose execution transitions' journals are parsed, so the labels
    recorded inside one are positions of the copy like any other."""
    opened = copy.deepcopy(dict(document))
    for event in opened["export"]["events"]:
        payload = event.get("payload")
        evidence = payload.get("evidence") if isinstance(payload, Mapping) else None
        record = evidence.get("authenticated_record") if isinstance(evidence, dict) else None
        if event.get("kind") != "execution.transition" or not isinstance(record, str):
            continue
        try:
            parsed = json.loads(record)
        except (ValueError, RecursionError):
            continue
        if isinstance(parsed, dict) and isinstance(evidence, dict):
            evidence["authenticated_record"] = _Journal(parsed)
    return opened


def rewrite(
    document: Mapping[str, Any],
    names: Mapping[str, str],
    text: Callable[[str], str],
    key: Callable[[str], str],
) -> dict[str, Any]:
    """A copy of `document` rewritten in one pass: the label at every position `collect`
    reads becomes its name in `names`, every other string becomes `text` of it and every
    mapping key `key` of it.

    Each string is rewritten once, from its source text. So a label whose text reads like
    the name another label is given, such as a comment `host-000001` in a history whose one
    host is given `host-000001`, never turns that host's name into the comment's.

    A list of writers is sorted again once its names are replaced, since evaluation reads a
    fact's writers sorted and a pseudonym need not sort where the name it replaced did beside
    a catalog writer that is kept.
    """
    opened = _opened(document)
    placed: set[tuple[int, Any]] = set()
    writers: set[int] = set()

    def visit(container: Any, at: Any, kind: str) -> None:
        value = _value(container, at)
        if _label(value) and value in names:
            placed.add((id(container), at))
            if kind == "writer":
                writers.add(id(container))

    positions(opened, visit)

    def walk(value: Any) -> Any:
        # `opened` holds every container visited above until this returns, so no id is reused.
        if isinstance(value, Mapping):
            rewritten = {
                key(str(name)): names[child] if (id(value), name) in placed else walk(child)
                for name, child in value.items()
            }
            if isinstance(value, _Journal):
                return json.dumps(rewritten, ensure_ascii=False, separators=(",", ":"))
            return rewritten
        if isinstance(value, (list, tuple)):
            items = [
                names[child] if (id(value), index) in placed else walk(child)
                for index, child in enumerate(value)
            ]
            if id(value) in writers:
                items.sort()
            return items
        if isinstance(value, str):
            return text(value)
        return value

    result: dict[str, Any] = walk(opened)
    return result


# The fields whose strings are JSON the kernel writes: a bundle's Cedar schema and a
# settlement's provider journal.
_EMBEDDED = frozenset({"cedar_schema", "authenticated_record"})


def _vocabulary_field(path: tuple[str, ...]) -> bool:
    return bool(path) and (
        path[-1] in VOCABULARY_FIELDS
        or path[-2:] in {("thresholds", "value"), ("evidence", "reason")}
        or (len(path) > 1 and path[-2] in {"arguments", "claimed_context"})
    )


def _kept_words(value: Any, path: tuple[str, ...] = ()) -> Iterator[str]:
    if isinstance(value, Mapping):
        # A signal fact's source version is its source's registration number (`_plan`).
        if value.get("source_kind") == "signal" and isinstance(value.get("source_version"), str):
            yield value["source_version"]
        for name, child in value.items():
            yield str(name)
            yield from _kept_words(child, (*path, str(name)))
    elif isinstance(value, (list, tuple)):
        for child in value:
            yield from _kept_words(child, path)
    elif isinstance(value, str):
        if _vocabulary_field(path):
            yield value
        # Only the JSON the kernel itself embeds is read: a person's text that happens to
        # parse as JSON, such as a comment, is replaced whole, so nothing in it is kept.
        if path and path[-1] in _EMBEDDED:
            try:
                inner = json.loads(value)
            except (ValueError, RecursionError):
                return
            yield from _kept_words(inner, path)


def vocabulary(document: Mapping[str, Any]) -> frozenset[str]:
    """Every word a fixture of this export keeps wherever the kernel wrote it.

    That is every word of `PUBLIC_WORDS` (the catalog's, Cedar's, the kernel's reason codes and
    a case link's fixed text), every field name, every value at a vocabulary field and a
    signal fact's source version, with each whole token of them. A label whose text is one of
    these is replaced only where it was recorded: anywhere else the text is that word, which
    the fixture shows anyway, and never says which label it was.
    """
    found = _tokens(
        _kept_words({"export": document["export"], "candidates": document["candidates"]})
    )
    return PUBLIC_WORDS | found


def _whole_only(value: str, kind: str) -> bool:
    """Whether a label is found only as a whole value or a whole JSON string: an operation
    ref or a version with no letter in it, such as `7` or `2026-10-01`."""
    return kind in EXACT_TYPES and not any(character.isalpha() for character in value)


class Finder:
    """Where labels are found inside other text: a label as a whole token, and an operation
    ref or a version with no letter in it only as a whole JSON string, as a journal record
    carries it."""

    def __init__(self, labels: Mapping[str, str]) -> None:
        """`labels` maps each label to its type."""
        tokens = sorted(
            (value for value, kind in labels.items() if not _whole_only(value, kind)),
            key=lambda value: (-len(value), value),
        )
        self.quoted: dict[str, str] = {}
        for value, kind in labels.items():
            if kind in EXACT_TYPES:
                for form in (json.dumps(value), json.dumps(value, ensure_ascii=False)):
                    self.quoted[form] = value
        alternatives = []
        if tokens:
            alternatives.append(
                f"(?P<token>(?<![{WORD}])(?:" + "|".join(map(re.escape, tokens)) + f")(?![{WORD}]))"
            )
        if self.quoted:
            forms = sorted(self.quoted, key=lambda form: (-len(form), form))
            alternatives.append("(?P<quoted>" + "|".join(map(re.escape, forms)) + ")")
        self.pattern = re.compile("|".join(alternatives)) if alternatives else None

    def search(self, value: str) -> bool:
        return self.pattern is not None and self.pattern.search(value) is not None

    def sub(self, value: str, names: Mapping[str, str]) -> str:
        """`value` with every label found in it replaced by its name in `names`."""
        if self.pattern is None:
            return value

        def replace(found: re.Match[str]) -> str:
            if found.lastgroup == "token":
                return names[found.group(0)]
            return json.dumps(names[self.quoted[found.group(0)]])

        return self.pattern.sub(replace, value)


def every_string(value: Any) -> Iterable[str]:
    """Every key and string in a document, and every one inside the JSON a string carries."""
    if isinstance(value, Mapping):
        for name, child in value.items():
            yield str(name)
            yield from every_string(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            yield from every_string(child)
    elif isinstance(value, str):
        yield value
        if value.startswith(("{", "[")):
            try:
                inner = json.loads(value)
            except (ValueError, RecursionError):
                return
            yield from every_string(inner)


def is_sanitized(document: Mapping[str, Any]) -> bool:
    """Whether a fixture's every identifier is a pseudonym and every label position holds one.

    This is the shape a build writes, checked again wherever a fixture is read, so neither a
    real export wrapped by hand nor a fixture edited back to source text can be checked or
    re-recorded. It reads the same positions the sanitizer collects from.
    """
    try:
        text = json.dumps(document, ensure_ascii=False).lower()
        if any(not _IDENTIFIER.fullmatch(found) for found in _EVERY_UUID.findall(text)):
            return False
        return all(
            _PSEUDONYM.fullmatch(value) or _DERIVED_KEY.fullmatch(value)
            for value in collect(document)
        )
    except (KeyError, TypeError, ValueError, RecursionError):
        return False
