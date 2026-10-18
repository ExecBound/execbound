# SPDX-License-Identifier: AGPL-3.0-only
"""Replay regression fixtures: the format, the check and the sanitizer (docs/REPLAY.md).

Every history here is pure, built by `replay_fixtures`, so none of this needs a database. The
committed fixtures are checked here too (RF10); a fresh build from the signal world, on
PostgreSQL, is in `test_replay_fixture_worlds.py` (RF9).
"""

import hashlib
import json
import re
from datetime import timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from replay_fixtures import (
    approved_entries,
    asserted_outcome,
    chain_export,
    executor_evidence,
    make_capture,
    replay_case,
    transition_event,
)

from execbound.execution.models import TerminalEvidence
from execbound.operations import PRODUCTION_ACTIONS
from execbound.policy.models import ContextSetting, Rule, Ruleset
from execbound.provider.connector_record import ConnectorExchange, sign_exchange
from execbound.provider.models import SignedJournal, parse_provider, signature
from execbound.replay import sanitize
from execbound.replay.fixture import (
    FixtureError,
    ReplayFixture,
    check,
    expected_outcomes,
    parse,
    render,
    rerecord,
)
from execbound.replay.pseudonyms import (
    VOCABULARY_FIELDS,
    collect,
    is_sanitized,
    positions,
    vocabulary,
)
from execbound.replay.verify import verify_export
from execbound.requests import ActionRequest, ResourceSelector
from execbound.resolution.models import intent_hash

UUID_TEXT = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
HOST = "ws-77.corp.example"
STOP_REASON = f"Paused while {HOST} is checked"
COMMENT = f"Approved after the call about {HOST}"
PERSON = "Dana Q. Example"
# Text the one secret definition matches, assembled at run time so secret scanners do not read
# this source as holding a credential.
SHAPED_NOTE = " ".join(("Bearer", "abcdefgh12345678"))
# What an agent may send as its case, which the first transition of its execution carries.
CASE = {
    "source": "acme-soar",
    "case_id": "INC0012345",
    "url": "https://acme-corp.service-now.com/now/sir/INC0012345",
}
# Text an owner or an operator types, each carrying `acme` so one search finds any survivor.
OPERATION_REF = "acme-prod-falcon-contain"
RESOURCE_VERSION = "acme-cmdb-2026-10-01"
MAPPING_VERSION = "acme-map-7"
REFERENCE = "acme ticket 7731"
TARGET_HOST = "ws-88.acme.example"
NOTE = "Ask Dana before isolating anything at acme"
# An operator's change number typed as a reconciliation reason: shaped like a code, but not one
# the kernel writes.
TICKET = "CHG0031337"
# An incident's version as the owner's context writer recorded it, and that writer's own name,
# which the bundle's context settings permit beside the catalog's default writer.
INCIDENT_VERSION = "acme-snow-INC0012345-rev2"
WRITER = "acme_soc_sync"


def world(*, comment=COMMENT, stop_reason=STOP_REASON):
    """A complete approved isolation, a labelled principal and a stop, all pure."""
    case = replay_case(production=True)
    entries = approved_entries(case)
    kind, payload = entries[4]
    entries[4] = (kind, {**payload, "comment": comment})
    first = entries[1]
    later = first.semantic_time + timedelta(seconds=5)
    stop = str(uuid4())
    entries += [
        (
            "principal.labelled",
            {"principal_id": str(first.identity.principal_id), "label": PERSON},
        ),
        (
            "tenant.stop_activated",
            {
                "stop_id": stop,
                "reason": stop_reason,
                "replay": {"version": 1, "semantic_time": later.isoformat()},
            },
        ),
        (
            "tenant.stop_released",
            {
                "stop_id": stop,
                "reason": "Released",
                "replay": {"version": 1, "semantic_time": (later + timedelta(1)).isoformat()},
            },
        ),
    ]
    export = chain_export(entries, (case["bundle"],))
    # A candidate with no approval rules: the recorded review is no longer asked for.
    candidate = case["bundle"].model_copy(update={"bundle_id": uuid4(), "approval_policies": ""})
    return export, candidate


@pytest.fixture
def built():
    export, candidate = world()
    return export, candidate, sanitize.build(export, export.head, (candidate,))


def edited(raw, change):
    document = json.loads(raw)
    change(document)
    return (json.dumps(document, indent=1, sort_keys=True, ensure_ascii=False) + "\n").encode()


def first_transition(entries, **payload):
    """The first transition with what admission adds to it (`execution/store.py` `event`)."""
    kind, attempted = entries[0]
    assert attempted["to_state"] == "ATTEMPTED"
    entries[0] = (kind, {**attempted, **payload})


def terminal_reason(entries, reason):
    kind, settled = entries[-1]
    assert settled["to_state"] == "EXECUTED"
    entries[-1] = (kind, {**settled, "reason": reason})


def every_kind_world(
    operation_ref=OPERATION_REF,
    resource_version=RESOURCE_VERSION,
    mapping_version=MAPPING_VERSION,
    *,
    comment="Approved for acme",
    stop_reason="Paused for acme",
    cedar_comment="",
):
    """A history carrying every kind of text the sanitizer replaces.

    An owner's own operation ref, resource and mapping versions and rule notes; a request's
    reference and hostname target; an incident's version and a context writer the owner named;
    the agent's case on the first transition, where admission writes it; an operator's reason
    on the settlement; an approval comment, two stop reasons and a principal's label.
    `cedar_comment` is put before the bundle's authorization policies, and so the candidate's.
    """
    case = replay_case(production=True)
    [mapping] = case["bundle"].mappings
    writers = (WRITER, "soc_analyst")
    bundle = case["bundle"].model_copy(
        update={
            "context_settings": (
                ContextSetting(
                    context_contract_version=mapping.context_contract_version,
                    source_kind="incident",
                    max_age_seconds=300,
                    permitted_writers=writers,
                ),
            ),
            "mappings": (
                mapping.model_copy(
                    update={
                        "operation_ref": operation_ref,
                        "action": "endpoint.isolate",
                        "mapping_version": mapping_version,
                    }
                ),
            ),
            "ruleset": Ruleset(
                rules=(Rule(id="contain", action="endpoint.isolate", effect="ALLOW", note=NOTE),)
            ),
            "authorization_policies": cedar_comment + case["bundle"].authorization_policies,
        }
    )
    resolved = case["resolved"]
    resolved = resolved.model_copy(
        update={
            "request": ActionRequest(
                operation_ref=operation_ref,
                target=ResourceSelector(kind="hostname", value=TARGET_HOST),
                arguments=resolved.request.arguments,
                reference=REFERENCE,
                claimed_context=resolved.request.claimed_context,
            ),
            "resource_version": resource_version,
            "mapping_version": mapping_version,
            "facts": tuple(
                fact.model_copy(update={"source_version": resource_version})
                if fact.source_version == resolved.resource_version
                else fact.model_copy(
                    update={"source_version": INCIDENT_VERSION, "permitted_writers": writers}
                )
                if fact.source_kind == "incident"
                else fact
                for fact in resolved.facts
            ),
        }
    )
    case = {**case, "bundle": bundle, "resolved": resolved}
    entries = approved_entries(case)
    first_transition(entries, operation_ref=operation_ref, external_case=CASE)
    terminal_reason(entries, TICKET)
    kind, payload = entries[4]
    entries[4] = (kind, {**payload, "comment": comment})
    later = entries[1].semantic_time + timedelta(seconds=5)
    stop = str(uuid4())
    entries += [
        ("principal.labelled", {"principal_id": str(uuid4()), "label": "Dana at acme"}),
        (
            "tenant.stop_activated",
            {
                "stop_id": stop,
                "reason": stop_reason,
                "replay": {"version": 1, "semantic_time": later.isoformat()},
            },
        ),
        (
            "tenant.stop_released",
            {
                "stop_id": stop,
                "reason": "Released for acme",
                "replay": {"version": 1, "semantic_time": (later + timedelta(1)).isoformat()},
            },
        ),
    ]
    export = chain_export(entries, (bundle,))
    candidate = bundle.model_copy(update={"bundle_id": uuid4(), "approval_policies": ""})
    return export, candidate


def strings(value):
    """Every string in a document, and every string inside the JSON a string carries."""
    if isinstance(value, dict):
        for name, child in value.items():
            yield name
            yield from strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from strings(child)
    elif isinstance(value, str):
        yield value
        if value.startswith("{"):
            try:
                yield from strings(json.loads(value))
            except ValueError:
                pass


def values_at(value, key):
    """Every value a key holds anywhere in a document, embedded JSON included."""
    if isinstance(value, dict):
        for name, child in value.items():
            if name == key:
                yield child
            yield from values_at(child, key)
    elif isinstance(value, list):
        for child in value:
            yield from values_at(child, key)
    elif isinstance(value, str) and value.startswith("{"):
        try:
            yield from values_at(json.loads(value), key)
        except ValueError:
            pass


def payloads(raw, kind):
    return [
        event["payload"] for event in json.loads(raw)["export"]["events"] if event["kind"] == kind
    ]


def test_rf1_a_fixture_replays_to_its_recorded_outcomes(built):
    export, _, raw = built
    fixture, found = check(raw)
    assert found == []
    assert fixture.format == "execbound.replay-fixture" and fixture.version == 1
    rows = fixture.expected.baseline.decisions
    assert [row.recorded_effect for row in rows] == ["REQUIRE_APPROVAL", "ELIGIBLE", "ELIGIBLE"]
    assert all(row.outcome == "EXECUTED" for row in rows)
    assert fixture.expected.baseline.complete
    [candidate] = fixture.expected.candidates
    assert candidate.candidate_hash == fixture.candidates[0].content_hash
    assert any(row.differences for row in candidate.decisions)
    # The sequence and the times are kept; the identifiers are not.
    assert [event.sequence for event in fixture.export.events] == [
        event.sequence for event in export.events
    ]
    assert [event.occurred_at for event in fixture.export.events] == [
        event.occurred_at for event in export.events
    ]


def test_rf1_a_history_with_missing_facts_is_recorded_with_its_reasons():
    case = replay_case(production=True)
    entries = approved_entries(case)
    # Without the human review, the admission that consumes it cannot be reconstructed.
    del entries[3]
    export = chain_export(entries, (case["bundle"],))
    fixture, found = check(sanitize.build(export, export.head, ()))
    assert found == []
    assert not fixture.expected.baseline.complete
    last = fixture.expected.baseline.decisions[-1]
    assert last.effect == "UNRESOLVED" and last.reasons


@pytest.mark.parametrize(
    "run,field,value",
    [
        ("baseline", "effect", "DENY"),
        ("baseline", "reasons", ["HARD_LIMIT:tenant-total-isolation"]),
        ("baseline", "outcome", "NOT_EXECUTED"),
        ("candidate", "effect", "ELIGIBLE"),
        ("candidate", "dependencies", ["00000000-0000-4000-8000-000000000001"]),
    ],
)
def test_rf2_one_edited_expectation_fails_and_names_its_sequence(built, run, field, value):
    _, _, raw = built

    def change(document):
        rows = (
            document["expected"]["baseline"]["decisions"]
            if run == "baseline"
            else document["expected"]["candidates"][0]["decisions"]
        )
        rows[0][field] = value

    sequence = parse(raw).expected.baseline.decisions[0].sequence
    _, found = check(edited(raw, change))
    name = "baseline" if run == "baseline" else "candidate 1"
    assert found == [f"{name} sequence {sequence} {field}"]


def test_rf2_a_lost_decision_and_a_changed_completeness_are_named(built):
    _, _, raw = built

    def change(document):
        document["expected"]["baseline"]["complete"] = False
        document["expected"]["candidates"][0]["decisions"].pop()

    last = parse(raw).expected.baseline.decisions[-1].sequence
    _, found = check(edited(raw, change))
    assert found == ["baseline complete", f"candidate 1 sequence {last} decision"]


def test_rf2_a_decision_recorded_twice_is_named(built):
    # Rows are matched by sequence, and replay records one decision per sequence, so a second
    # row for a sequence, however alike, is a difference and not a duplicate key overwritten.
    _, _, raw = built

    def change(document):
        baseline = document["expected"]["baseline"]["decisions"]
        baseline.append(dict(baseline[0]))
        candidate = document["expected"]["candidates"][0]["decisions"]
        candidate.append(dict(candidate[-1]))

    fixture = parse(raw)
    first = fixture.expected.baseline.decisions[0].sequence
    last = fixture.expected.candidates[0].decisions[-1].sequence
    _, found = check(edited(raw, change))
    assert found == [f"baseline sequence {first} decision", f"candidate 1 sequence {last} decision"]


def test_rf2_a_candidate_edited_without_re_recording_fails_on_its_content_hash(built):
    # A Cedar comment decides nothing, so only the candidate's recorded hash can tell that the
    # candidate the fixture checks is not the one its expectations were recorded for.
    _, _, raw = built

    def change(document):
        candidate = document["candidates"][0]
        candidate["authorization_policies"] = "// edited\n" + candidate["authorization_policies"]

    _, found = check(edited(raw, change))
    assert found == ["candidate 1 candidate_hash"]


@pytest.mark.parametrize("part", ["payload", "head", "bundle", "candidate"])
def test_rf3_an_edited_history_is_refused(built, part):
    _, _, raw = built

    def change(document):
        if part == "payload":
            event = next(
                e for e in document["export"]["events"] if e["kind"] == "tenant.stop_activated"
            )
            event["payload"]["reason"] = "reason-000009"
        elif part == "head":
            document["trusted_head"]["sequence"] -= 1
        elif part == "bundle":
            document["export"]["bundles"][0]["approval_policies"] = ""
        else:
            # Pseudonym-shaped, so the fixture still reads as sanitized and verification is
            # what refuses it.
            document["candidates"][0]["tenant_id"] = "00000000-0000-4000-8000-0000000fffff"

    with pytest.raises(FixtureError) as refusal:
        check(edited(raw, change))
    assert (
        refusal.value.code
        == {
            "payload": "INVALID_CHAIN",
            "head": "HEAD_MISMATCH",
            "bundle": "INVALID_FROZEN_PLAN",
            "candidate": "INVALID_CANDIDATE",
        }[part]
    )


@pytest.mark.parametrize("defect", ["version", "format", "duplicate", "float", "extra", "many"])
def test_rf3_a_fixture_outside_the_format_is_unavailable(built, defect):
    _, _, raw = built
    text = raw.decode()
    ending = '\n "version": 1\n}\n'
    assert text.endswith(ending)
    if defect == "duplicate":
        text = text.removesuffix(ending) + '\n "version": 1,' + ending
    elif defect == "float":
        text = text.removesuffix(ending) + '\n "version": 1.0\n}\n'
    else:
        document = json.loads(text)
        if defect == "version":
            document["version"] = 2
        elif defect == "format":
            document["format"] = "execbound.replay-fixture-v2"
        elif defect == "extra":
            document["mapping"] = {}
        else:
            document["candidates"] = document["candidates"] * 9
        text = json.dumps(document)
    with pytest.raises(FixtureError) as refusal:
        parse(text.encode())
    assert refusal.value.code == "FIXTURE_UNAVAILABLE"


def incident_facts(document):
    return [
        fact
        for event in document["export"]["events"]
        if isinstance(event["payload"].get("frozen"), dict)
        for fact in event["payload"]["frozen"]["facts"]
        if fact["source_kind"] == "incident"
    ]


@pytest.mark.parametrize(
    "part", ["identifier", "case", "reason", "version", "note", "source version", "writer"]
)
def test_rf3_a_fixture_still_holding_source_text_is_refused_as_unsanitized(part):
    export, candidate = every_kind_world()
    raw = sanitize.build(export, export.head, (candidate,))

    def change(document):
        events = document["export"]["events"]
        if part == "source version":
            incident_facts(document)[0]["source_version"] = INCIDENT_VERSION
        elif part == "writer":
            incident_facts(document)[0]["permitted_writers"] = sorted((WRITER, "soc_analyst"))
        elif part == "identifier":
            events[0]["event_id"] = str(uuid4())
        elif part == "case":
            events[0]["payload"]["external_case"]["case_id"] = CASE["case_id"]
        elif part == "reason":
            events[-4]["payload"]["reason"] = TICKET
        elif part == "version":
            document["export"]["bundles"][0]["mappings"][0]["mapping_version"] = MAPPING_VERSION
        else:
            document["candidates"][0]["ruleset"]["rules"][0]["note"] = NOTE

    unsanitized = edited(raw, change)
    for read in (check, rerecord):
        with pytest.raises(FixtureError) as refusal:
            read(unsanitized)
        assert refusal.value.code == "FIXTURE_NOT_SANITIZED"


def test_rf3_an_export_wrapped_by_hand_as_a_fixture_is_refused():
    # A history the build refuses cannot become a fixture by being wrapped in one and given its
    # expectations by re-recording.
    export, candidate = world()
    history = verify_export(export, export.head)
    wrapped = ReplayFixture(
        format="execbound.replay-fixture",
        version=1,
        sanitization={"version": 1, "identifiers": 0, "labels": 0, "digests": 0},
        trusted_head=export.head,
        export=export,
        candidates=(candidate,),
        expected=expected_outcomes(history, (candidate,)),
    )
    raw = render(wrapped)
    for read in (parse, check, rerecord):
        with pytest.raises(FixtureError) as refusal:
            read(raw)
        assert refusal.value.code == "FIXTURE_NOT_SANITIZED"


@pytest.mark.parametrize("part", ["candidate policy", "expectation"])
def test_rf3_a_fixture_edited_to_hold_a_secret_is_refused_by_reading(built, part):
    # A candidate's policy text is no label position, so the shape check alone would take a
    # secret typed into it, and re-recording would write it into a new fixture. Reading screens
    # the whole fixture with the one secret definition, as the build screens what it writes.
    _, _, raw = built

    def change(document):
        if part == "candidate policy":
            candidate = document["candidates"][0]
            policies = candidate["authorization_policies"]
            candidate["authorization_policies"] = f"// {SHAPED_NOTE}\n{policies}"
        else:
            document["expected"]["baseline"]["decisions"][0]["reasons"] = [SHAPED_NOTE]

    secret = edited(raw, change)
    for read in (parse, check, rerecord):
        with pytest.raises(FixtureError) as refusal:
            read(secret)
        assert refusal.value.code == "PRIVATE_DATA"
        assert "Bearer" not in str(refusal.value) + repr(refusal.value)


def test_rf4_a_build_is_deterministic_and_rerecording_is_byte_identical(built):
    export, candidate, raw = built
    assert sanitize.build(export, export.head, (candidate,)) == raw
    assert rerecord(raw) == raw
    assert rerecord(rerecord(raw)) == raw


def test_rf5_no_source_identifier_or_label_survives(built):
    export, candidate, raw = built
    text = raw.decode()
    source = export.model_dump_json() + candidate.model_dump_json()
    identifiers = set(UUID_TEXT.findall(source))
    assert len(identifiers) > 10
    lowered = text.lower()
    for identifier in identifiers:
        assert identifier not in lowered
        assert identifier.replace("-", "") not in lowered
    for label in ("device-01", HOST, STOP_REASON, COMMENT, PERSON, "Dana"):
        assert label not in text
    # The scenario's own key, `example`, is a substring of HOST, so its absence is read from
    # the keys themselves: every one is a pseudonym and none is a source key.
    document = json.loads(raw)
    keys = set(values_at(document, "idempotency_key"))
    sources = set(values_at(json.loads(export.model_dump_json()), "idempotency_key"))
    assert "example" in sources and keys
    assert all(re.fullmatch(r"key-\d{6}", key) for key in keys)
    assert not keys & sources
    assert "example" not in set(strings(document))
    fixture = parse(raw)
    assert fixture.sanitization.identifiers >= len(identifiers) - 8
    assert fixture.sanitization.labels >= 4
    # Pseudonyms keep order: every identifier is a ranked pseudonym.
    assert set(UUID_TEXT.findall(lowered)) <= {
        f"00000000-0000-4000-8000-{n:012x}" for n in range(1, len(identifiers) + 1)
    }
    # The journal is re-signed under the published fixture key, and says so.
    assert '\\"key_id\\":\\"replay-fixture\\"' in text


def test_rf5_the_agents_case_on_the_first_transition_never_reaches_a_fixture():
    # Admission writes the case at the top of the first transition and nowhere else: the
    # frozen plan there carries no request, and a capture's request is normalized.
    case = replay_case(production=True)
    entries = approved_entries(case)
    first_transition(entries, operation_ref="endpoint.isolate", external_case=CASE)
    export = chain_export(entries, (case["bundle"],))
    raw = sanitize.build(export, export.head, ())
    text = raw.decode()
    for value in (*CASE.values(), "acme", "INC0012345", "service-now"):
        assert value not in text
    [attempted] = [p for p in payloads(raw, "execution.transition") if p["to_state"] == "ATTEMPTED"]
    assert attempted["external_case"] == {
        "source": "source-000001",
        "case_id": "case-000001",
        "url": "https://case.invalid/url-000001",
    }
    # A catalog action is vocabulary and is kept.
    assert attempted["operation_ref"] == "endpoint.isolate"
    assert check(raw)[1] == []


def test_rf5_every_kind_of_label_is_replaced_by_its_typed_pseudonym():
    export, candidate = every_kind_world()
    raw = sanitize.build(export, export.head, (candidate,))
    text = raw.decode()
    for value in ("acme", TICKET, "Dana", "INC0012345", "ws-88"):
        assert value not in text
    document = json.loads(raw)
    found = {
        key: set(values_at(document, key))
        for key in (
            "operation_ref",
            "resource_version",
            "mapping_version",
            "expected_version",
            "resulting_version",
            "source_version",
            "reference",
            "note",
            "comment",
        )
    }
    assert found["operation_ref"] == {"operation-000001"}
    # Ranked by their original text: the resource's, the mapping's, the incident's and the
    # journal's resulting version.
    assert found["resource_version"] == found["expected_version"] == {"version-000001"}
    assert found["mapping_version"] == {"version-000002"}
    assert found["source_version"] == {"version-000001", "version-000003"}
    assert found["resulting_version"] == {"version-000004"}
    # The writer the owner named becomes a pseudonym; the catalog's own default is a word the
    # catalog defines and is kept, and each fact's writers stay sorted, as evaluation reads them.
    writers = [list(item) for item in values_at(document, "permitted_writers")]
    assert {name for item in writers for name in item} == {
        "inventory_sync",
        "soc_analyst",
        "writer-000001",
    }
    assert all(item == sorted(item) for item in writers)
    assert ["soc_analyst", "writer-000001"] in writers
    assert found["reference"] == {"reference-000001"}
    assert found["note"] == {"note-000001"}
    assert found["comment"] == {"comment-000001"}
    hosts = {
        target["value"]
        for target in values_at(document, "target")
        if isinstance(target, dict) and target.get("kind") == "hostname"
    }
    assert hosts == {"host-000001"}
    # A reference's key is derived again from the pseudonyms, so the request still validates.
    keys = set(values_at(document, "idempotency_key"))
    assert keys and all(re.fullmatch(r"reference-000001-[0-9a-f]{32}", key) for key in keys)
    transitions = payloads(raw, "execution.transition")
    [attempted] = [p for p in transitions if p["to_state"] == "ATTEMPTED"]
    assert attempted["external_case"]["case_id"] == "case-000001"
    assert transitions[-1]["reason"] == "reason-000001"
    assert {p["reason"] for p in payloads(raw, "tenant.stop_activated")} == {"reason-000002"}
    fixture, found_differences = check(raw)
    assert found_differences == [] and rerecord(raw) == raw
    assert [row.effect for row in fixture.expected.baseline.decisions] == [
        "REQUIRE_APPROVAL",
        "ELIGIBLE",
        "ELIGIBLE",
    ]


def test_rf5_a_short_version_or_a_ref_inside_a_catalog_name_is_replaced_only_where_it_is_one():
    # An operation ref may be a word the catalog spells inside its own names (`isolate` in
    # `endpoint.isolate`), and a version a bare number the journal also writes as one, so
    # both are replaced only as whole values and whole strings, never as tokens of other text.
    # A version with no letter in it is not looked for as a token either, so the numbers a
    # policy's comment holds stay as they are.
    note = "// at most 2 isolations in 1 hour\n"
    export, candidate = every_kind_world(
        operation_ref="isolate", resource_version="1", mapping_version="2", cedar_comment=note
    )
    raw = sanitize.build(export, export.head, (candidate,))
    document = json.loads(raw)
    assert set(values_at(document, "operation_ref")) == {"operation-000001"}
    assert set(values_at(document, "action")) == {"endpoint.isolate"}
    assert set(values_at(document, "resource_version")) == {"version-000001"}
    assert set(values_at(document, "expected_version")) == {"version-000001"}
    assert set(values_at(document, "mapping_version")) == {"version-000002"}
    assert set(values_at(document, "mutation_count")) == {1}
    assert all(text.startswith(note) for text in authorization(document))
    assert check(raw)[1] == []


def authorization(document):
    return [
        bundle["authorization_policies"]
        for bundle in (*document["export"]["bundles"], *document["candidates"])
    ]


def test_rf5_an_owners_version_or_ref_inside_policy_text_is_replaced_there_too():
    # A version or an operation ref with a letter in it names something as a host does, so a
    # Cedar comment that copies one is rewritten with the pseudonym its position got, in the
    # recorded bundle and the candidate alike.
    note = f"// rollout of {MAPPING_VERSION} for {OPERATION_REF} approved by CAB\n"
    export, candidate = every_kind_world(cedar_comment=note)
    raw = sanitize.build(export, export.head, (candidate,))
    text = raw.decode()
    assert MAPPING_VERSION not in text and OPERATION_REF not in text
    document = json.loads(raw)
    [version] = set(values_at(document, "mapping_version"))
    [ref] = set(values_at(document, "operation_ref"))
    assert re.fullmatch(r"version-\d{6}", version) and re.fullmatch(r"operation-\d{6}", ref)
    rewritten = f"// rollout of {version} for {ref} approved by CAB\n"
    policies = authorization(document)
    assert len(policies) == 2 and all(text.startswith(rewritten) for text in policies)
    fixture, found = check(raw)
    assert found == [] and rerecord(raw) == raw


def test_rf5_no_label_position_is_a_field_the_fixture_keeps():
    # A label is left as it is only where its text is a kept word, and a vocabulary field is one
    # source of those words, so no field a label is recorded at may be one.
    export, candidate = every_kind_world()
    document = {
        "export": json.loads(export.model_dump_json()),
        "candidates": [json.loads(candidate.model_dump_json())],
    }
    fields = set()
    positions(document, lambda container, key, kind: fields.add(key))
    named = {field for field in fields if isinstance(field, str)}
    assert {"reason", "comment", "source_version", "resulting_version"} <= named
    assert not named & VOCABULARY_FIELDS


def test_rf5_a_signal_facts_source_version_is_kept_and_any_other_facts_is_a_label():
    # A signal fact's source version is its source's registration number, which evaluation
    # compares with the number its records carry, so a version label that is the same number
    # (a resource at version `7`) is replaced where it was recorded and never there.
    def fact(kind, version):
        return {"name": kind, "source_kind": kind, "source_version": version}

    plan = {"facts": [fact("signal", "7"), fact("incident", "8"), fact("inventory", "9")]}
    document = {
        "export": {
            "bundles": [],
            "events": [{"kind": "execution.evaluated", "payload": {"frozen": plan}}],
        },
        "candidates": [],
    }
    assert collect(document) == {"8": "version", "9": "version"}
    words = vocabulary(document)
    assert "7" in words and not {"8", "9"} & words


def test_rf5_text_a_person_typed_lends_no_kept_word():
    # A comment that parses as JSON is replaced whole, so its keys are not field names the
    # fixture keeps, and the resource id it names is still sought everywhere else.
    export, candidate = world(comment=json.dumps({"device-01": "isolated"}))
    candidate = candidate.model_copy(
        update={
            "authorization_policies": "// device-01 is the lab host\n"
            + candidate.authorization_policies
        }
    )
    raw = sanitize.build(export, export.head, (candidate,))
    assert "device-01" not in raw.decode()
    assert check(raw)[1] == []


def recorded_labels(document):
    """The hostname targets, the resource ids (the journal's command included) and the
    approval comments a fixture holds."""
    return (
        {
            target["value"]
            for target in values_at(document, "target")
            if isinstance(target, dict) and target.get("kind") == "hostname"
        },
        set(values_at(document, "resource_provider_id")),
        set(values_at(document, "comment")),
    )


@pytest.mark.parametrize("comment", ["host-000001", "resource-000001"])
def test_rf5_each_label_is_replaced_once_from_its_own_text(monkeypatch, comment):
    # A comment may read like another label's pseudonym: the history's one host becomes
    # `host-000001` and its one resource `resource-000001`. Each label is replaced from its own
    # text, once, so the host and the resource keep theirs, in the journal too, and the comment
    # gets its own; none is replaced again because a pseudonym reads like another label. The
    # survival search is set aside here to show the replacement alone.
    monkeypatch.setattr(sanitize, "_survives", lambda raw, identifiers, labels: False)
    export, candidate = every_kind_world(comment=comment)
    raw = sanitize.build(export, export.head, (candidate,))
    assert recorded_labels(json.loads(raw)) == (
        {"host-000001"},
        {"resource-000001"},
        {"comment-000001"},
    )


@pytest.mark.parametrize(
    "comment,refused",
    [("host-000001", True), ("resource-000001", True), ("host-000002", False)],
)
def test_rf5_a_label_that_reads_as_another_labels_pseudonym_is_refused(comment, refused):
    # Where a comment's text is the pseudonym another label is given, that text stands in the
    # fixture as the other label's pseudonym, so the build refuses it as surviving rather than
    # let two labels share one name. A comment that reads as a pseudonym no label is given
    # becomes a fixture under its own.
    export, candidate = every_kind_world(comment=comment)
    if refused:
        with pytest.raises(FixtureError) as refusal:
            sanitize.build(export, export.head, (candidate,))
        assert refusal.value.code == "FIXTURE_NOT_SANITIZED"
        return
    raw = sanitize.build(export, export.head, (candidate,))
    assert comment not in raw.decode()
    assert recorded_labels(json.loads(raw)) == (
        {"host-000001"},
        {"resource-000001"},
        {"comment-000001"},
    )
    assert check(raw)[1] == []


def test_rf7_a_one_word_comment_that_is_a_token_of_a_time_is_refused():
    # Times are kept as they were, and a label that is no kept word is sought as a whole token
    # in every string. A comment `00` is a token of every `+00:00` time the history holds, so
    # replacing it there would break the time, and the build refuses rather than write it.
    export, candidate = every_kind_world(comment="00")
    source = json.loads(export.model_dump_json())
    times = [p["replay"]["semantic_time"] for p in values_at(source, "payload") if "replay" in p]
    assert times and all(time.endswith("+00:00") for time in times)
    assert "00" not in vocabulary({"export": source, "candidates": []})
    with pytest.raises(FixtureError) as refusal:
        sanitize.build(export, export.head, (candidate,))
    assert refusal.value.code == "FIXTURE_NOT_FAITHFUL"


def cedar(document):
    return [
        bundle[part]
        for bundle in (*document["export"]["bundles"], *document["candidates"])
        for part in ("authorization_policies", "approval_policies")
    ]


@pytest.mark.parametrize(
    "case",
    [
        "a vendor's operation name as the ref",
        "a payload key as the comment",
        "a source kind as the stop reason",
        "a fact's value as the comment",
        "a state as the comment",
    ],
)
def test_rf5_a_label_that_is_also_a_kept_word_is_replaced_only_where_it_was_recorded(case):
    # An owner may name a ref after the vendor's own operation, and a person may type one word
    # the history also holds as vocabulary. The label is replaced where it was recorded and the
    # word is kept where the catalog or the kernel wrote it, so the history still verifies and
    # replays the same: the fixture shows that word anyway, and never which label it was.
    if case == "a vendor's operation name as the ref":
        # The rule id is the same word, and a rule id is kept.
        export, candidate = every_kind_world(operation_ref="contain")
    elif case == "a payload key as the comment":
        export, candidate = world(comment="approved")
    elif case == "a source kind as the stop reason":
        export, candidate = world(stop_reason="incident")
    elif case == "a fact's value as the comment":
        export, candidate = world(comment="production")
    else:
        export, candidate = world(comment="APPROVED")
    source = {
        "export": json.loads(export.model_dump_json()),
        "candidates": [json.loads(candidate.model_dump_json())],
    }
    raw = sanitize.build(export, export.head, (candidate,))
    document = json.loads(raw)
    if case == "a vendor's operation name as the ref":
        assert set(values_at(document, "operation_ref")) == {"operation-000001"}
        # The plan's intent and the journal's command alike.
        assert set(values_at(document, "provider_operation")) == {"contain"}
        assert set(values_at(document, "id")) == {"contain"}
    elif case == "a source kind as the stop reason":
        # Ranked after the release's `Released`, which sorts first.
        assert {p["reason"] for p in payloads(raw, "tenant.stop_activated")} == {"reason-000002"}
        assert "incident" in set(values_at(document, "source_kind"))
    else:
        assert {p["comment"] for p in payloads(raw, "approval.transition") if "comment" in p} == {
            "comment-000001"
        }
        if case == "a payload key as the comment":
            assert any("approved" in p for p in payloads(raw, "execution.transition"))
        elif case == "a fact's value as the comment":
            assert "production" in set(values_at(document, "value"))
            assert [text.count("production") for text in cedar(document)] == [
                text.count("production") for text in cedar(source)
            ]
        else:
            assert "APPROVED" in set(values_at(document, "to_state"))
    fixture, found = check(raw)
    assert found == [] and rerecord(raw) == raw
    assert [row.effect for row in fixture.expected.baseline.decisions] == [
        "REQUIRE_APPROVAL",
        "ELIGIBLE",
        "ELIGIBLE",
    ]


@pytest.mark.parametrize("position", ["comment", "stop reason"])
@pytest.mark.parametrize(
    "word",
    [
        # The fixture's own field names, and the words its expectations hold.
        "complete",
        "expected",
        "baseline",
        "format",
        "labels",
        "provenance",
        "UNRESOLVED",
        "EFFECT",
        # The published key its journal is signed again under.
        "replay-fixture",
        # The text of a case link's pseudonym, `https://case.invalid/url-000001`.
        "https",
        "case",
        "invalid",
    ],
)
def test_rf5_a_label_that_is_a_word_the_fixture_writes_itself_still_becomes_a_fixture(
    word, position
):
    # A fixture writes words its source need never have held: its own field names, the words
    # of its expectations, the published key's id and a case link's pseudonym. A one-word
    # comment or stop reason that is one of them is replaced where it was recorded, and the
    # word stays where the fixture itself wrote it.
    if position == "comment":
        export, candidate = every_kind_world(comment=word)
    else:
        export, candidate = every_kind_world(stop_reason=word)
    raw = sanitize.build(export, export.head, (candidate,))
    if position == "comment":
        recorded = {p["comment"] for p in payloads(raw, "approval.transition") if "comment" in p}
        assert recorded == {"comment-000001"}
    else:
        [recorded] = {p["reason"] for p in payloads(raw, "tenant.stop_activated")}
        assert re.fullmatch(r"reason-\d{6}", recorded)
    assert any(
        re.search(rf"(?<![\w-]){re.escape(word)}(?![\w-])", text)
        for text in strings(json.loads(raw))
    )
    fixture, found = check(raw)
    assert found == [] and rerecord(raw) == raw


@pytest.mark.parametrize(
    "word",
    [
        # Cedar's own words, which every policy's text spells.
        "permit",
        "forbid",
        "when",
        "principal",
        "resource",
        "Action",
        # A reason code the kernel writes on the history's settlement.
        "PROVIDER_RESPONSE",
    ],
)
def test_rf5_a_label_that_is_a_cedar_word_or_a_kernel_reason_code_stays_where_the_kernel_wrote_it(
    word,
):
    # Cedar's words are in the text of every bundle and candidate, and the kernel's reason
    # codes in the transitions it writes, whatever history a fixture came from. A one-word
    # comment that is one of them is replaced where it was recorded, and the policies and the
    # settlement keep the word, so the history still verifies and replays the same.
    case = replay_case(production=True)
    entries = approved_entries(case)
    kind, payload = entries[4]
    entries[4] = (kind, {**payload, "comment": word})
    terminal_reason(entries, "PROVIDER_RESPONSE")
    export = chain_export(entries, (case["bundle"],))
    candidate = case["bundle"].model_copy(update={"bundle_id": uuid4(), "approval_policies": ""})
    source = {
        "export": json.loads(export.model_dump_json()),
        "candidates": [json.loads(candidate.model_dump_json())],
    }
    raw = sanitize.build(export, export.head, (candidate,))
    document = json.loads(raw)
    recorded = {p["comment"] for p in payloads(raw, "approval.transition") if "comment" in p}
    assert recorded == {"comment-000001"}
    assert cedar(document) == cedar(source)
    assert payloads(raw, "execution.transition")[-1]["reason"] == "PROVIDER_RESPONSE"
    fixture, found = check(raw)
    assert found == [] and rerecord(raw) == raw
    assert [row.effect for row in fixture.expected.baseline.decisions] == [
        "REQUIRE_APPROVAL",
        "ELIGIBLE",
        "ELIGIBLE",
    ]


@pytest.mark.parametrize(
    "reason,kept",
    [
        ("PROVIDER_RESPONSE", True),
        ("INCONCLUSIVE_JOURNAL", True),
        (TICKET, False),
        ("Reconciled after the vendor call", False),
    ],
)
def test_rf5_a_kernel_reason_code_is_kept_and_any_other_reason_is_replaced(reason, kept):
    case = replay_case(production=True)
    entries = approved_entries(case)
    terminal_reason(entries, reason)
    export = chain_export(entries, (case["bundle"],))
    raw = sanitize.build(export, export.head, ())
    settled_reason = payloads(raw, "execution.transition")[-1]["reason"]
    assert settled_reason == (reason if kept else "reason-000001")
    assert (reason in raw.decode()) is kept


def test_rf5_the_principal_label_and_other_informational_text_never_reach_a_fixture(built):
    _, _, raw = built
    fixture = parse(raw)
    labelled = [event for event in fixture.export.events if event.kind == "principal.labelled"]
    assert len(labelled) == 1 and dict(labelled[0].payload) == {}


def test_rf6_a_secret_shaped_candidate_note_is_refused_and_nothing_is_written(tmp_path):
    export, candidate = world()
    noted = candidate.model_copy(
        update={
            "ruleset": Ruleset(
                rules=(
                    Rule(
                        id="isolate",
                        action="endpoint.isolate",
                        effect="ALLOW",
                        note=SHAPED_NOTE,
                    ),
                )
            )
        }
    )
    source, head = tmp_path / "history.json", tmp_path / "history.head.json"
    source.write_text(export.model_dump_json())
    head.write_text(export.head.model_dump_json())
    named = tmp_path / "candidate.json"
    named.write_text(noted.model_dump_json())
    output = tmp_path / "fixture.json"
    with pytest.raises(FixtureError) as refusal:
        sanitize.run_build(source, head, (named,), output)
    assert refusal.value.code == "PRIVATE_DATA"
    assert not output.exists()
    assert "Bearer" not in str(refusal.value) + repr(refusal.value)


def graph_case():
    """An identity disable bound to Microsoft Graph, which settles on the connector's record."""
    case = replay_case("identity.disable")
    spec = PRODUCTION_ACTIONS.bound("graph", "identity.disable")
    resolved = case["resolved"]
    intent = resolved.intent.model_copy(
        update={"provider": spec.provider, "provider_operation": spec.provider_operation}
    )
    return {**case, "resolved": resolved.model_copy(update={"intent": intent})}


def connector_evidence(capture):
    """What a Graph settlement retains: ExecBound's own signed record of the exchange."""
    intent = capture.frozen.intent
    exchange = ConnectorExchange(
        operation_id=capture.operation_id,
        account_id=intent.account_id,
        intent_hash=intent_hash(intent),
        plan_hash=capture.decision.plan_hash,
        provider=intent.provider,
        provider_operation=intent.provider_operation,
        frozen=capture.frozen.resource_version,
        observed=capture.frozen.resource_version,
        window_ms=12,
        status=204,
        outcome="EXECUTED",
    )
    record = sign_exchange(exchange, "connector-v1", b"fixture-only-connector-key-32-by").decode()
    return TerminalEvidence(
        operation_id=exchange.operation_id,
        account_id=exchange.account_id,
        intent_hash=exchange.intent_hash,
        plan_hash=exchange.plan_hash,
        outcome="EXECUTED",
        reason="EXECUTED",
        proof_digest=hashlib.sha256(record.encode()).hexdigest(),
        authenticated_record=record,
        window_ms=exchange.window_ms,
    )


def settled(kind):
    """One settlement of each kind version 1 cannot re-sign, as the kernel writes it."""
    case = graph_case() if kind == "connector" else replay_case()
    capture = make_capture(case)
    if kind == "attested":
        proof = executor_evidence(capture).model_dump(mode="json")
        settlement = transition_event(
            capture, "DISPATCH_COMMITTED", "EXECUTED", evidence=proof, tier="ATTESTED"
        )
    elif kind == "asserted":
        said = asserted_outcome(capture).model_dump(mode="json")
        settlement = transition_event(
            capture, "DISPATCH_COMMITTED", "EXECUTED", asserted=said, tier="ASSERTED"
        )
    elif kind == "unsettled assertion":
        # `outcomes._settle_report` keeps an executor's word with no tier where it settles
        # nothing.
        said = asserted_outcome(capture, outcome="CANCELLED_NOT_EXECUTED").model_dump(mode="json")
        settlement = transition_event(
            capture,
            "DISPATCH_COMMITTED",
            "INDETERMINATE",
            asserted=said,
            reason="EXECUTOR_REPORT",
        )
    else:
        # No tier: the envelope is chosen from the captured command's provider, so only the
        # record's own parse can tell it is not a provider journal.
        proof = connector_evidence(capture).model_dump(mode="json")
        settlement = transition_event(capture, "DISPATCH_COMMITTED", "EXECUTED", evidence=proof)
    export = chain_export([capture, settlement], (case["bundle"],))
    verify_export(export, export.head)  # the source itself verifies: the refusal is the build's
    return export


@pytest.mark.parametrize("kind", ["attested", "asserted", "unsettled assertion", "connector"])
def test_rf6_externally_executed_evidence_is_refused(kind):
    export = settled(kind)
    with pytest.raises(FixtureError) as refusal:
        sanitize.build(export, export.head, ())
    assert refusal.value.code == "FIXTURE_UNSUPPORTED_EVIDENCE"


def test_rf6_a_candidate_for_another_tenant_or_too_many_candidates_are_refused():
    export, candidate = world()
    foreign = candidate.model_copy(update={"tenant_id": uuid4()})
    for candidates in ((foreign,), (candidate,) * 9):
        with pytest.raises(FixtureError) as refusal:
            sanitize.build(export, export.head, candidates)
        assert refusal.value.code == "INVALID_CANDIDATE"


def test_rf6_a_source_that_does_not_verify_is_refused_with_its_code():
    export, candidate = world()
    wrong = export.head.model_copy(update={"sequence": export.head.sequence - 1})
    with pytest.raises(FixtureError) as refusal:
        sanitize.build(export, wrong, (candidate,))
    assert refusal.value.code == "HEAD_MISMATCH"


def test_rf7_a_substitution_that_leaves_a_value_behind_is_refused(monkeypatch):
    export, candidate = world()
    monkeypatch.setattr(sanitize, "_substitute", lambda value, names: value)
    with pytest.raises(FixtureError) as refusal:
        sanitize.build(export, export.head, (candidate,))
    assert refusal.value.code == "FIXTURE_NOT_SANITIZED"


def test_rf7_a_label_that_survives_inside_other_text_is_refused(monkeypatch):
    export, candidate = world()
    # A candidate's Cedar names the resource in a comment. Nothing replay binds reads that
    # text, so only the search inside every string can find the resource id left in it: as a
    # whole value, `device-01` is replaced everywhere it appears.
    commented = "// device-01 is the lab host\n"
    candidate = candidate.model_copy(
        update={"authorization_policies": commented + candidate.authorization_policies}
    )
    assert sanitize.build(export, export.head, (candidate,))
    original = sanitize._substitute

    def keep_the_comment(value, names):
        return value if value.startswith(commented) else original(value, names)

    monkeypatch.setattr(sanitize, "_substitute", keep_the_comment)
    with pytest.raises(FixtureError) as refusal:
        sanitize.build(export, export.head, (candidate,))
    assert refusal.value.code == "FIXTURE_NOT_SANITIZED"


def test_rf7_a_version_left_inside_policy_text_is_refused(monkeypatch):
    # The search inside every string looks for a version with a letter in it as a token, as it
    # does a host, so a Cedar comment the substitution left still naming one is found.
    note = f"// rollout of {MAPPING_VERSION} approved by CAB\n"
    export, candidate = every_kind_world(cedar_comment=note)
    original = sanitize._substitute

    def keep_the_comment(value, names):
        return value if value.startswith(note) else original(value, names)

    monkeypatch.setattr(sanitize, "_substitute", keep_the_comment)
    with pytest.raises(FixtureError) as refusal:
        sanitize.build(export, export.head, (candidate,))
    assert refusal.value.code == "FIXTURE_NOT_SANITIZED"


def test_rf7_a_sanitized_history_that_replays_differently_is_refused(monkeypatch):
    export, candidate = world()
    original = sanitize._substitute

    def move_the_target(value, names):
        # Internally consistent once rehashed, but no longer the same decisions.
        return "development" if value == "production" else original(value, names)

    monkeypatch.setattr(sanitize, "_substitute", move_the_target)
    with pytest.raises(FixtureError) as refusal:
        sanitize.build(export, export.head, (candidate,))
    assert refusal.value.code == "FIXTURE_NOT_FAITHFUL"


def test_rf7_an_output_that_fails_verification_is_refused(monkeypatch):
    export, candidate = world()
    monkeypatch.setattr(sanitize, "_resign", lambda text: text)
    with pytest.raises(FixtureError) as refusal:
        sanitize.build(export, export.head, (candidate,))
    assert refusal.value.code == "FIXTURE_NOT_FAITHFUL"


def test_rf5_the_journal_is_re_signed_under_a_published_fixture_key(built):
    _, _, raw = built
    [evidence] = [
        event.payload["evidence"]
        for event in parse(raw).export.events
        if "evidence" in event.payload
    ]
    journal = parse_provider(evidence["authenticated_record"].encode(), SignedJournal)
    assert journal.key_id == sanitize.FIXTURE_KEY_ID == "replay-fixture"
    assert journal.signature == signature(
        journal.record, journal.key_id, sanitize.FIXTURE_JOURNAL_KEY
    )
    assert journal.record.command_hash == journal.record.command.command_hash
    assert b"fixture" in sanitize.FIXTURE_JOURNAL_KEY


COMMITTED = Path(__file__).resolve().parent / "fixtures" / "replay"


def test_rf10_the_committed_fixtures_are_the_signal_world_and_the_demonstration():
    assert {path.name for path in COMMITTED.glob("*.json")} >= {
        "signal-world-v1.json",
        "two-provider-tenant-0-v1.json",
    }


@pytest.mark.parametrize("path", sorted(COMMITTED.glob("*.json")), ids=lambda path: path.stem)
def test_rf10_each_committed_fixture_replays_and_rerecords_byte_for_byte(path):
    raw = path.read_bytes()
    # Reading refuses an unsanitized fixture anyway; this says so of the committed ones.
    assert is_sanitized(json.loads(raw))
    fixture, found = check(raw)
    assert found == [], found
    assert fixture.expected.baseline.decisions
    assert rerecord(raw) == raw


def test_rf5_an_opaque_digest_pseudonym_never_spells_a_small_identifier():
    # Test worlds and seeds use small-integer UUIDs; a zero-padded counter would end in one.
    small = {UUID(int=value).hex for value in range(1, 4097)}
    for rank in range(1, 4097):
        pseudonym = sanitize._digest_pseudonym(rank)
        assert re.fullmatch(r"[0-9a-f]{64}", pseudonym)
        assert not any(pseudonym[start : start + 32] in small for start in range(33))
    assert sanitize._digest_pseudonym(1) < sanitize._digest_pseudonym(2)
