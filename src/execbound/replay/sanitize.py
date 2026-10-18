# SPDX-License-Identifier: AGPL-3.0-only
"""Pseudonymize a replay export for a regression fixture, keeping every decision replay reads.

A fixture is built from an export and its candidates by replacing what identifies a tenant
and keeping what decides. Every UUID becomes an order-preserving pseudonym, open text that
names a host, an object, a case, a writer, an owner's operation ref or version, a person's
note or a reason becomes a typed pseudonym at the position it was recorded at, and anywhere
else it appears unless it is a word the fixture keeps anyway (`pseudonyms.py` says which
positions and which words), and payloads of informational kinds are reduced to the keys
replay reads. Times, the event order, the catalog's vocabulary and policy text are kept, so
this is pseudonymization and not anonymization (docs/REPLAY.md, "Regression fixtures").

Every digest that covers a replaced value is then recomputed, in the order the digests depend
on one another, and the provider journal is re-signed under a published key that signs
nothing real. Nothing is written unless the result verifies, replays to the same classified
outcomes under the mapping, carries no secret, keeps no source identifier or label that is
not a kept word, and holds a pseudonym at every label position. The mapping itself is never
kept.
"""

import hashlib
import json
import re
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import UUID

from execbound.audit import GENESIS, _event_hash, canonical_json
from execbound.policy.models import BundleContent
from execbound.provider.models import (
    JournalRecord,
    ProviderCommand,
    ProviderError,
    SignedJournal,
    parse_provider,
    sign_journal,
)
from execbound.replay.fixture import (
    FORMAT,
    MAX_CANDIDATES,
    Expected,
    FixtureError,
    ReplayFixture,
    Sanitization,
    expected_outcomes,
    parse,
    render,
    write_fixture,
)
from execbound.replay.models import (
    MAX_EXPORT_BYTES,
    AuditEvent,
    DecisionCapture,
    ReplayExport,
    TrustedHead,
    VerifiedHistory,
    plain_json,
)
from execbound.replay.pseudonyms import (
    LABEL_TYPES,
    Finder,
    collect,
    every_string,
    identifier,
    is_sanitized,
    pseudonym,
    rewrite,
    vocabulary,
)
from execbound.replay.runner import MAX_CANDIDATE_BYTES, read_bounded, strict_json
from execbound.replay.verify import ReplayValidationError, parse_export, verify_export
from execbound.requests import derive_key
from execbound.resolution.models import CanonicalIntent, intent_hash, plan_hash
from execbound.secrets import find_secrets

# Published on purpose. A fixture's journal is re-signed under it because its source's
# provider key is never available offline and a recomputed command hash needs a signature
# over it. The key id says so, and the runtime refuses the key as any connector's evidence
# key, Gate account's journal key or sample key (`provider.published_keys`), so a journal
# signed under it settles nothing.
FIXTURE_JOURNAL_KEY = b"execbound-replay-fixture-journal-key-v1"
FIXTURE_KEY_ID = "replay-fixture"

# The kinds whose payloads replay reads whole. Every other kind keeps only what replay reads
# of it: `execution_id`, which carries an earlier execution's taint forward, a bundle event's
# `bundle_id` and `content_hash`, which verification binds to the export's bundles, and a
# dispatch attempt's `precondition_class`.
_READ_KINDS = frozenset(
    {
        "execution.evaluated",
        "execution.transition",
        "approval.transition",
        "tenant.stop_activated",
        "tenant.stop_released",
    }
)

_UUID = re.compile(r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}")
_EVERY_UUID = re.compile(r"(?=([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}))")
_HEX32 = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{32}(?![0-9A-Fa-f])")
_HEX64 = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{64}(?![0-9A-Fa-f])")
_HEX_RUN = re.compile(r"[0-9a-f]{32,}")
# Keys whose values are digests recomputed below rather than replaced as opaque values.
_DERIVED_KEYS = frozenset(
    {
        "content_hash",
        "intent_hash",
        "plan_hash",
        "proof_digest",
        "command_hash",
        "signature",
        "event_hash",
        "previous_hash",
    }
)


@dataclass(frozen=True)
class Names:
    """One build's mapping. It lives for the build and is never written.

    `labels` names every label, for the positions it was recorded at; `sought` names those
    that are not a word the fixture keeps, which are replaced wherever else they appear and
    which `finder` looks for inside other text.
    """

    identifiers: Mapping[str, str]
    undashed: Mapping[str, str]
    labels: Mapping[str, str]
    sought: Mapping[str, str]
    digests: Mapping[str, str]
    finder: Finder


def _relabel(value: str, labels: Mapping[str, str], finder: Finder) -> str:
    if value in labels:
        return labels[value]
    return finder.sub(value, labels)


def _substitute(value: str, names: Names) -> str:
    """One string with every sought label, identifier and opaque digest replaced.

    A label at a position it was recorded at is replaced by `rewrite` and never reaches this.
    Derived digests are left for `_rehash`, which recomputes them once what they cover has
    been replaced.
    """
    value = _relabel(value, names.sought, names.finder)
    value = _UUID.sub(
        lambda found: names.identifiers.get(found.group(0).lower(), found.group(0)), value
    )
    value = _HEX32.sub(
        lambda found: names.undashed.get(found.group(0).lower(), found.group(0)), value
    )
    return _HEX64.sub(
        lambda found: names.digests.get(found.group(0).lower(), found.group(0)), value
    )


def _key(value: str, names: Names) -> str:
    """A mapping key keeps its name; only an identifier in it is replaced."""
    return _UUID.sub(
        lambda found: names.identifiers.get(found.group(0).lower(), found.group(0)), value
    )


def _walk(value: Any, text: Callable[[str], str], key: Callable[[str], str]) -> Any:
    if isinstance(value, Mapping):
        return {key(name): _walk(child, text, key) for name, child in value.items()}
    if isinstance(value, (list, tuple)):
        return [_walk(child, text, key) for child in value]
    if isinstance(value, str):
        return text(value)
    return value


def _strings(value: Any) -> Iterator[str]:
    if isinstance(value, Mapping):
        for name, child in value.items():
            yield str(name)
            yield from _strings(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            yield from _strings(child)
    elif isinstance(value, str):
        yield value


def _reduced(event: Mapping[str, Any]) -> dict[str, Any]:
    kind = event["kind"]
    if kind in _READ_KINDS:
        return dict(event)
    kept = {"execution_id"}
    if kind.startswith("policy.bundle_"):
        kept |= {"bundle_id", "content_hash"}
    if kind == "execution.dispatch_attempt":
        kept.add("precondition_class")
    payload = {name: child for name, child in event["payload"].items() if name in kept}
    return {**event, "payload": payload}


def _digest_pseudonym(rank: int) -> str:
    """An opaque digest's stand-in: forty-eight `e`s and a sixteen-digit counter.

    Zero padding would let a small counter end in the undashed form of a small-integer UUID
    (`...000a` is `UUID(int=10)`), which the survival check would then find in the output.
    No thirty-two-character window of this form is all counter, so none can be one.
    """
    return "e" * 48 + f"{rank:016x}"


def _ranked(values: Iterable[str], name: Callable[[int], str]) -> dict[str, str]:
    """Rank values by their original text, so a pseudonym sorts where its original did."""
    return {value: name(rank) for rank, value in enumerate(sorted(set(values)), start=1)}


def _names(document: Mapping[str, Any], derived: set[str], kept: frozenset[str]) -> Names:
    labels = collect(document)
    label_names: dict[str, str] = {}
    for kind in LABEL_TYPES:
        values = sorted(value for value, typed in labels.items() if typed == kind)
        label_names |= {value: pseudonym(kind, rank) for rank, value in enumerate(values, 1)}
    sought = {value: name for value, name in label_names.items() if value not in kept}
    finder = Finder({value: labels[value] for value in sought})
    # Identifiers and opaque digests are read after labels are replaced, so a value that only
    # ever appeared inside a label (an idempotency key's derived digest) is not counted.
    relabelled = rewrite(
        document, label_names, lambda value: _relabel(value, sought, finder), lambda value: value
    )
    identifiers: set[str] = set()
    digests: set[str] = set()
    for text in _strings(relabelled):
        identifiers.update(found.lower() for found in _UUID.findall(text))
        identifiers.update(str(UUID(found)) for found in _HEX32.findall(text))
        digests.update(found.lower() for found in _HEX64.findall(text))
    dashed = _ranked(identifiers, identifier)
    return Names(
        identifiers=dashed,
        undashed={old.replace("-", ""): new.replace("-", "") for old, new in dashed.items()},
        labels=label_names,
        sought=sought,
        digests=_ranked(digests - derived - {GENESIS}, _digest_pseudonym),
        finder=finder,
    )


def _derived(history: VerifiedHistory, candidates: Sequence[BundleContent]) -> set[str]:
    """Every digest `_rehash` recomputes, read from the source before anything is replaced."""
    found = {history.export.head.event_hash}
    bundles = {bundle.bundle_id: bundle for bundle in history.export.bundles}
    for bundle in (*history.export.bundles, *candidates):
        versions = bundle.security_versions
        found.update((versions.bundle, versions.authorization, versions.approval, versions.limits))
    for entry in history.events:
        capture = entry.capture
        if capture is not None:
            found.add(intent_hash(capture.frozen.intent))
            found.add(plan_hash(capture.frozen, bundles[capture.bundle_id].security_versions))
        payload = plain_json(entry.event.payload)
        for record in _records(payload):
            payload = {**payload, "record": json.loads(record)}
        found.update(_keyed_digests(payload))
        found.update((entry.event.previous_hash, entry.event.event_hash))
    return found


def _records(payload: Mapping[str, Any]) -> list[str]:
    evidence = payload.get("evidence")
    if isinstance(evidence, Mapping) and isinstance(evidence.get("authenticated_record"), str):
        return [evidence["authenticated_record"]]
    return []


def _keyed_digests(value: Any) -> Iterator[str]:
    if isinstance(value, Mapping):
        for name, child in value.items():
            if name in _DERIVED_KEYS and isinstance(child, str):
                yield child.lower()
            else:
                yield from _keyed_digests(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            yield from _keyed_digests(child)


def _refuse_unsupported(history: VerifiedHistory) -> None:
    """Version 1 re-signs only a provider journal. An executor's Ed25519 record, an ES256
    JWS, a connector's record and an assertion carry signatures or words this cannot redo,
    so a history holding one is refused rather than rewritten."""
    for entry in history.events:
        payload = entry.event.payload
        if (
            entry.settlement_tier is not None
            or entry.asserted_outcome is not None
            or (
                entry.event.kind == "execution.transition"
                and ("tier" in payload or "asserted" in payload)
            )
        ):
            raise FixtureError("FIXTURE_UNSUPPORTED_EVIDENCE")
        if entry.terminal_evidence is not None:
            try:
                parse_provider(entry.terminal_evidence.authenticated_record.encode(), SignedJournal)
            except ProviderError:
                raise FixtureError("FIXTURE_UNSUPPORTED_EVIDENCE") from None


def _pair(pairs: dict[str, str], old: str, new: str) -> None:
    if pairs.setdefault(old, new) != new:
        raise FixtureError("FIXTURE_NOT_FAITHFUL")


def _apply(document: Any, pairs: Mapping[str, str]) -> Any:
    return _walk(
        document,
        lambda value: _HEX64.sub(lambda found: pairs.get(found.group(0), found.group(0)), value),
        lambda value: value,
    )


def _bundle(value: Mapping[str, Any]) -> BundleContent:
    return BundleContent.model_validate_json(canonical_json(value))


def _attempted_plan(frozen: Mapping[str, Any], bundle: BundleContent) -> str:
    """The plan hash an attempt carries, computed exactly as verification recomputes it."""
    envelope = {
        name: plain_json(value)
        for name, value in frozen.items()
        if name not in {"request", "resolved_at"}
    }
    envelope.update(version=1, security_versions=bundle.security_versions.model_dump(mode="json"))
    return hashlib.sha256(canonical_json(envelope).encode()).hexdigest()


def _resign(text: str) -> str:
    """A journal with its command hash recomputed, signed under the fixture key."""
    try:
        raw = json.loads(text)
        command = ProviderCommand.model_validate_json(canonical_json(raw["record"]["command"]))
        record = parse_provider(
            canonical_json({**raw["record"], "command_hash": command.command_hash}).encode(),
            JournalRecord,
        )
        return sign_journal(record, FIXTURE_KEY_ID, FIXTURE_JOURNAL_KEY).model_dump_json()
    except (KeyError, TypeError, ValueError, ProviderError):
        pass
    raise FixtureError("FIXTURE_NOT_FAITHFUL")


def _rederive_keys(document: dict[str, Any]) -> None:
    """A request with a reference carries the key derived from it, so both move together."""
    for event in document["export"]["events"]:
        frozen = event["payload"].get("frozen")
        request = frozen.get("request") if isinstance(frozen, Mapping) else None
        if isinstance(request, dict) and isinstance(request.get("reference"), str):
            target = request["target"]
            request["idempotency_key"] = derive_key(
                request["operation_ref"], target["kind"], target["value"], request["reference"]
            )


def _rehash(
    history: VerifiedHistory, document: dict[str, Any]
) -> tuple[ReplayExport, tuple[BundleContent, ...]]:
    """Recompute every digest over the replaced values, in the order they depend on each other.

    Bundle hashes and security versions first, since plans bind them; then intent and plan
    hashes; then each journal's command hash, its signature and the evidence's proof digest;
    and last the audit chain and its head. Each old digest is replaced by value wherever it
    appears, so a copy of a plan hash in an approval binding moves with the plan.
    """
    export = document["export"]
    pairs: dict[str, str] = {}
    old_bundles = {bundle.bundle_id: bundle for bundle in history.export.bundles}
    new_bundles = {}
    for old, raw in zip(history.export.bundles, export["bundles"], strict=True):
        new = _bundle(raw)
        new_bundles[new.bundle_id] = new
        for before, after in zip(
            old.security_versions.model_dump().values(),
            new.security_versions.model_dump().values(),
            strict=True,
        ):
            _pair(pairs, before, after)
    document = _apply(document, pairs)
    export = document["export"]
    pairs = {}
    for entry, event in zip(history.events, export["events"], strict=True):
        payload = event["payload"]
        if entry.capture is not None:
            old_capture = entry.capture
            capture = DecisionCapture.model_validate_json(canonical_json(payload))
            _pair(pairs, intent_hash(old_capture.frozen.intent), intent_hash(capture.frozen.intent))
            _pair(
                pairs,
                plan_hash(old_capture.frozen, old_bundles[old_capture.bundle_id].security_versions),
                plan_hash(capture.frozen, new_bundles[capture.bundle_id].security_versions),
            )
        elif (
            event["kind"] == "execution.transition"
            and payload.get("to_state") == "ATTEMPTED"
            and isinstance(payload.get("frozen"), Mapping)
        ):
            source = entry.event.payload
            intent = CanonicalIntent.model_validate_json(
                canonical_json(payload["frozen"]["intent"])
            )
            _pair(pairs, source["intent_hash"], intent_hash(intent))
            bundle = new_bundles[UUID(payload["bundle_id"])]
            _pair(pairs, source["plan_hash"], _attempted_plan(payload["frozen"], bundle))
    document = _apply(document, pairs)
    export = document["export"]
    pairs = {}
    for event in export["events"]:
        evidence = event["payload"].get("evidence")
        if event["kind"] == "execution.transition" and isinstance(evidence, dict):
            record = _resign(evidence["authenticated_record"])
            evidence["authenticated_record"] = record
            _pair(pairs, evidence["proof_digest"], hashlib.sha256(record.encode()).hexdigest())
    document = _apply(document, pairs)
    export = document["export"]
    previous = GENESIS
    for event in export["events"]:
        event["previous_hash"] = previous
        event["event_hash"] = GENESIS
        row = AuditEvent.model_validate_json(canonical_json(event)).audit_row()
        event["event_hash"] = previous = _event_hash(row)
    export["head"] = {
        "version": 1,
        "tenant_id": export["tenant_id"],
        "sequence": len(export["events"]),
        "event_hash": previous,
    }
    return (
        parse_export(canonical_json(export).encode()),
        tuple(_bundle(raw) for raw in document["candidates"]),
    )


def _survives(raw: bytes, identifiers: set[str], labels: Mapping[str, str]) -> bool:
    """Whether any source identifier, dashed or not and in any case, is still anywhere in the
    output, or any sought label anywhere in its history or its candidates.

    A label is looked for as a whole value and, inside other text, as `Finder` finds it, in
    every string and in every string of the JSON a string carries, such as a journal record.
    A label that is a word the fixture keeps is not sought: where the kernel wrote that word
    it is the word, and `is_sanitized` holds every position a label was recorded at.

    The rest of the fixture is not searched for labels. Its expectations are replay's own
    classification of the sanitized history, which `build` holds equal to the source's under
    the mapping, so they hold replay's words and what that history holds; its head, format
    and counts are digests, numbers and the format's own names. A comment that reads one of
    those words, such as `complete`, is replaced where it was recorded and still becomes a
    fixture.
    """
    text = raw.decode("utf-8")
    lowered = text.lower()
    if identifiers & set(_EVERY_UUID.findall(lowered)):
        return True
    # The nil UUID identifies nothing, and the chain's genesis hash is sixty-four zeros.
    undashed = {source.replace("-", "") for source in identifiers} - {"0" * 32}
    for run in _HEX_RUN.findall(lowered):
        if any(run[start : start + 32] in undashed for start in range(len(run) - 31)):
            return True
    finder = Finder(labels)
    written = json.loads(text)
    history = {"export": written["export"], "candidates": written["candidates"]}
    return any(value in labels or finder.search(value) for value in every_string(history))


def _mapped(expected: Expected, names: Names) -> Any:
    """The source's expectations under the mapping, without the hashes a rename moves."""
    value = expected.model_dump(mode="json")
    for candidate in value["candidates"]:
        candidate.pop("candidate_hash")
    return _walk(
        value,
        lambda text: _UUID.sub(
            lambda found: names.identifiers.get(found.group(0).lower(), found.group(0)), text
        ),
        lambda text: text,
    )


def _candidates(
    export: ReplayExport, candidates: Sequence[BundleContent]
) -> tuple[BundleContent, ...]:
    if len(candidates) > MAX_CANDIDATES:
        raise FixtureError("INVALID_CANDIDATE")
    try:
        parsed = tuple(
            BundleContent.model_validate_json(candidate.model_dump_json())
            for candidate in candidates
        )
    except (ValueError, TypeError):
        raise FixtureError("INVALID_CANDIDATE") from None
    if any(
        candidate.tenant_id != export.tenant_id
        or len(candidate.model_dump_json().encode()) > MAX_CANDIDATE_BYTES
        for candidate in parsed
    ):
        raise FixtureError("INVALID_CANDIDATE")
    return parsed


def build(
    export: ReplayExport, head: TrustedHead, candidates: Sequence[BundleContent] = ()
) -> bytes:
    """A sanitized fixture of this history and these candidates, or a refusal by code."""
    candidates = _candidates(export, candidates)
    try:
        history = verify_export(export, head)
    except ReplayValidationError as refusal:
        raise FixtureError(refusal.code) from None
    _refuse_unsupported(history)
    if find_secrets([candidate.model_dump(mode="json") for candidate in candidates], limit=1):
        raise FixtureError("PRIVATE_DATA")
    try:
        recorded = expected_outcomes(history, candidates)
    except ReplayValidationError as refusal:
        raise FixtureError(refusal.code) from None
    source: dict[str, Any] = {
        "export": history.export.model_dump(mode="json"),
        "candidates": [candidate.model_dump(mode="json") for candidate in candidates],
    }
    identifiers = {found.lower() for found in _UUID.findall(canonical_json(source))}
    identifiers |= {str(UUID(found)) for text in _strings(source) for found in _HEX32.findall(text)}
    labels = collect(source)
    reduced: dict[str, Any] = {
        "export": {
            **source["export"],
            "events": [_reduced(event) for event in source["export"]["events"]],
        },
        "candidates": source["candidates"],
    }
    try:
        # The published key's id is a word every re-signed journal holds.
        kept = vocabulary(reduced) | {FIXTURE_KEY_ID}
        names = _names(reduced, _derived(history, candidates), kept)
        document = rewrite(
            reduced,
            names.labels,
            lambda value: _substitute(value, names),
            lambda value: _key(value, names),
        )
        _rederive_keys(document)
        sanitized, renamed = _rehash(history, document)
        replayed = verify_export(sanitized, sanitized.head)
        expected = expected_outcomes(replayed, renamed)
    except FixtureError:
        raise
    except (ReplayValidationError, ValueError, TypeError, KeyError, AttributeError, RecursionError):
        raise FixtureError("FIXTURE_NOT_FAITHFUL") from None
    raw = render(
        ReplayFixture(
            format=FORMAT,
            version=1,
            sanitization=Sanitization(
                version=1,
                identifiers=len(names.identifiers),
                labels=len(names.labels),
                digests=len(names.digests),
            ),
            trusted_head=sanitized.head,
            export=sanitized,
            candidates=renamed,
            expected=expected,
        )
    )
    written = json.loads(raw)
    if find_secrets(written, limit=1):
        raise FixtureError("PRIVATE_DATA")
    # Two nets: nothing sought survives anywhere, and every position a label is collected from
    # holds a pseudonym, which is also what reading a fixture checks.
    sought = {value: kind for value, kind in labels.items() if value not in kept}
    if _survives(raw, identifiers, sought) or not is_sanitized(written):
        raise FixtureError("FIXTURE_NOT_SANITIZED")
    replayed_value = expected.model_dump(mode="json")
    for candidate in replayed_value["candidates"]:
        candidate.pop("candidate_hash")
    if _mapped(recorded, names) != replayed_value:
        raise FixtureError("FIXTURE_NOT_FAITHFUL")
    return raw


def _read_json(path: Path, limit: int) -> bytes:
    raw = read_bounded(Path(path), limit)
    strict_json(raw)
    return raw


def run_build(
    source: Path, checkpoint: Path, candidates: Sequence[Path], output: Path
) -> ReplayFixture:
    """Read an export, its head and candidate files, and write one new sanitized fixture."""
    inputs = [Path(source), Path(checkpoint), *map(Path, candidates)]
    try:
        export = parse_export(read_bounded(Path(source), MAX_EXPORT_BYTES))
        head = TrustedHead.model_validate_json(_read_json(checkpoint, 4096))
    except ReplayValidationError as refusal:
        raise FixtureError(refusal.code) from None
    except (OSError, ValueError, TypeError, RecursionError):
        raise FixtureError() from None
    try:
        bundles = [
            BundleContent.model_validate_json(_read_json(path, MAX_CANDIDATE_BYTES))
            for path in candidates
        ]
    except (OSError, ValueError, TypeError, RecursionError):
        raise FixtureError("INVALID_CANDIDATE") from None
    raw = build(export, head, bundles)
    write_fixture(output, raw, inputs)
    return parse(raw)
