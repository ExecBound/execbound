# SPDX-License-Identifier: AGPL-3.0-only
"""The execbound.security-signal.v1 envelope (docs/SIGNALS.md, "What a producer sends").

Protocol tests: this file imports the envelope module, the standard library, pydantic, pytest
and jsonschema, and nothing else from ExecBound. What the stored record and the frozen plan make
of an envelope is tested beside them, in tests/test_signal_admit.py and
tests/test_signal_evidence.py.
"""

import ast
import json
from datetime import UTC, date, datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID

import pytest
from execbound_protocol import signals as protocol_signals
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from execbound.signals.envelope import (
    LONG_MAX,
    LONG_MIN,
    MAX_ENVELOPE_BYTES,
    EnvelopeError,
    SecuritySignal,
    canonical_json,
    parse_signal,
    record_digest,
)

SCHEMA = Path(__file__).parent.parent / "integrations/schemas/security-signal.v1.schema.json"
VALIDATOR = Draft202012Validator(json.loads(SCHEMA.read_text(encoding="utf-8")))
AT = datetime(2026, 9, 28, 12, 0, tzinfo=UTC)
EARLIER = "2026-09-28T11:00:00Z"


def body(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": "execbound.security-signal.v1",
        "source_event_id": "device-01:1727524800",
        "producer": {"name": "execbound-mde-producer", "version": "0.1.0"},
        "capability": "resource_compromise.v1",
        "verdict": "Medium",
        "confidence": 1000,
        "subject": {
            "kind": "resource",
            "account_id": "00000000-0000-0000-0000-00000000000a",
            "provider": "mock_crowdstrike",
            "resource_type": "endpoint",
            "provider_id": "device-01",
        },
        "observed_at": "2026-09-28T12:00:00+00:00",
    }
    value.update(changes)
    return value


def subject(**changes: object) -> dict[str, object]:
    value = body()["subject"]
    assert isinstance(value, dict)
    return {**value, **changes}


def raw(value: object) -> bytes:
    return json.dumps(value).encode()


# Every optional field, populated the way a real producer would.
OPTIONAL: dict[str, object] = {
    "severity": "High",
    "action": "endpoint.isolate",
    "request_reference": "change 4471",
    "expires_at": "2026-09-28T12:05:00+00:00",
    "attributes": {"risk_score": "Medium", "exposure_level": 72, "onboarded": True},
    "evidence_ref": "mde:machines/device-01/alerts",
    "evidence_digest": "0" * 64,
}


def test_a_valid_envelope_parses_and_digests_its_normalized_content():
    signal = parse_signal(raw(body()))
    assert signal.subject.provider_id == "device-01"
    assert signal.attributes == {} and signal.expires_at is None
    same_instant = parse_signal(raw(body(observed_at="2026-09-28T13:00:00+01:00")))
    reordered = parse_signal(json.dumps(dict(reversed(list(body().items())))).encode())
    assert record_digest(signal) == record_digest(same_instant) == record_digest(reordered)
    assert record_digest(parse_signal(raw(body(verdict="High")))) != record_digest(signal)


def test_the_digest_ignores_the_order_of_attributes():
    ordered = parse_signal(raw(body(attributes={"a": 1, "b": True, "c": "x"})))
    shuffled = parse_signal(raw(body(attributes={"c": "x", "a": 1, "b": True})))
    assert record_digest(ordered) == record_digest(shuffled)


def test_python_values_build_an_envelope_that_round_trips():
    """A producer may build one from Python values; JSON never yields these types."""
    signal = parse_signal(raw(body(**OPTIONAL)))
    assert SecuritySignal.model_validate(signal.model_dump()) == signal
    fields = signal.model_dump()
    built = SecuritySignal(
        **{
            **fields,
            "observed_at": datetime(2026, 9, 28, 17, 30, tzinfo=timezone(timedelta(hours=5.5))),
            "subject": {**fields["subject"], "account_id": UUID(int=10)},
        }
    )
    assert built.observed_at == AT and built.observed_at.tzinfo is UTC
    assert built.subject.account_id == UUID(int=10)
    assert record_digest(built) == record_digest(signal)


@pytest.mark.parametrize(
    "value",
    [
        datetime(2026, 9, 28, 12, 0),
        datetime(1, 1, 1, tzinfo=timezone(timedelta(hours=1))),
        datetime(9999, 12, 31, 23, 59, tzinfo=timezone(timedelta(hours=-1))),
        date(2026, 9, 28),
        AT.timestamp(),
    ],
    ids=["naive", "before-year-1-in-utc", "after-year-9999-in-utc", "date", "timestamp"],
)
@pytest.mark.parametrize("field", ["observed_at", "expires_at"])
def test_a_python_time_must_be_an_aware_datetime_inside_the_calendar(field, value):
    fields = parse_signal(raw(body(observed_at=EARLIER))).model_dump()
    with pytest.raises(ValidationError):
        SecuritySignal(**{**fields, field: value})


@pytest.mark.parametrize("value", [str(UUID(int=10)).upper(), UUID(int=10).int, UUID(int=10).bytes])
def test_a_python_account_is_a_uuid_or_its_canonical_spelling(value):
    fields = parse_signal(raw(body())).model_dump()
    with pytest.raises(ValidationError):
        SecuritySignal(**{**fields, "subject": {**fields["subject"], "account_id": value}})


def test_every_optional_field_parses_and_times_are_held_in_utc():
    signal = parse_signal(raw(body(**OPTIONAL, observed_at="2026-09-28T17:30:00+05:30")))
    assert None not in signal.model_dump().values()
    assert signal.observed_at.tzinfo is UTC and signal.expires_at is not None
    assert signal.expires_at.tzinfo is UTC
    assert signal.model_dump(mode="json")["observed_at"] == "2026-09-28T12:00:00Z"


# The digest is how a retry is recognised: signal_admit answers a resent envelope with its
# original receipt only when the digests match. A change to either value below changes the
# digest of every record already stored, and every retry of one becomes a
# CONFLICTING_DUPLICATE, so these values never change within v1.
GOLDEN = [
    (
        # Optional fields absent: pins that an absent field is written as null.
        body(request_reference="änd", attributes={"b": 2, "a": True}),
        '{"action":null,"attributes":{"a":true,"b":2},"capability":"resource_compromise.v1",'
        '"confidence":1000,"evidence_digest":null,"evidence_ref":null,"expires_at":null,'
        '"observed_at":"2026-09-28T12:00:00Z","producer":{"name":"execbound-mde-producer",'
        '"version":"0.1.0"},"request_reference":"änd","schema_version":'
        '"execbound.security-signal.v1","severity":null,"source_event_id":'
        '"device-01:1727524800","subject":{"account_id":"00000000-0000-0000-0000-00000000000a",'
        '"kind":"resource","provider":"mock_crowdstrike","provider_id":"device-01",'
        '"resource_type":"endpoint"},"verdict":"Medium"}',
        "6bc0f71cf7b0c8fed3f46ff4d7bdd28107a40418a92af789cbf147a66ab14ad3",
    ),
    (
        # Every optional field present, non-ASCII text in several scripts, a fraction of a
        # second and an offset that the canonical form turns into UTC.
        body(
            **{
                **OPTIONAL,
                "request_reference": "änd \u05e9\u05dc\u05d5\u05dd",
                "attributes": {"note": "café", "b": 2, "a": True},
                "evidence_ref": "\U0001d11e",
                "observed_at": "2026-09-28T13:00:00.25+01:00",
            }
        ),
        '{"action":"endpoint.isolate","attributes":{"a":true,"b":2,"note":"café"},'
        '"capability":"resource_compromise.v1","confidence":1000,"evidence_digest":'
        '"0000000000000000000000000000000000000000000000000000000000000000","evidence_ref":'
        '"\U0001d11e","expires_at":"2026-09-28T12:05:00Z","observed_at":'
        '"2026-09-28T12:00:00.250000Z","producer":{"name":"execbound-mde-producer",'
        '"version":"0.1.0"},"request_reference":"änd \u05e9\u05dc\u05d5\u05dd","schema_version":'
        '"execbound.security-signal.v1","severity":"High","source_event_id":'
        '"device-01:1727524800","subject":{"account_id":"00000000-0000-0000-0000-00000000000a",'
        '"kind":"resource","provider":"mock_crowdstrike","provider_id":"device-01",'
        '"resource_type":"endpoint"},"verdict":"Medium"}',
        "73351ee7bc5b2aef010187211d66a45ae99d774d760a449c0e6debd7025b612b",
    ),
]


@pytest.mark.parametrize(("value", "canonical", "digest"), GOLDEN, ids=["absent", "present"])
def test_the_canonical_form_and_its_digest_are_pinned(value, canonical, digest):
    signal = parse_signal(json.dumps(value, ensure_ascii=False).encode())
    assert canonical_json(signal.model_dump(mode="json")) == canonical
    assert record_digest(signal) == digest


# Times are RFC 3339 as `datetime.isoformat()` writes them, or with `Z`.
@pytest.mark.parametrize("field", ["observed_at", "expires_at"])
@pytest.mark.parametrize(
    "spelling",
    [
        AT.isoformat(),
        AT.replace(microsecond=123456).isoformat(),
        AT.astimezone(timezone(timedelta(hours=-7))).isoformat(),
        "2026-09-28T12:00:00Z",
        "2026-09-28T12:00:00.5Z",
        # The widest offsets RFC 3339 allows.
        "2026-09-29T11:00:00+23:59",
        "2026-09-28T12:00:00-23:59",
    ],
)
def test_rfc_3339_times_are_accepted_in_either_field(field, spelling):
    signal = parse_signal(raw(body(**{"observed_at": EARLIER, field: spelling})))
    assert getattr(signal, field) == datetime.fromisoformat(spelling)
    assert list(VALIDATOR.iter_errors(body(**{"observed_at": EARLIER, field: spelling}))) == []


# What the published pattern refuses, which a schema validator refuses too.
TIMES_BY_PATTERN = [
    1727524800,
    "1727524800",
    "1727524800000",
    "1727524800.5",
    "-1",
    "0",
    "2026-09-28T12:00:00,5Z",
    "2026-09-28T12:00Z",
    "2026-09-28T12:00:00+0000",
    # Offsets outside RFC 3339's ranges, which a lax parser would read as another offset.
    "2026-09-28T12:00:00+05:60",
    "2026-09-28T12:00:00+24:00",
    "2026-09-28T12:00:00-24:00",
    "2026-09-28T12:00:00.1234567Z",
    "2026-09-28t12:00:00Z",
    "2026-09-28T12:00:00z",
    "2026-09-28 12:00:00Z",
    "2026-09-28T12:00:00",
    "2026-09-28",
]
# What only the parser can refuse: not a calendar instant, or one an offset carries past the
# calendar's edge when it is converted to UTC.
TIMES_BY_CALENDAR = [
    "2026-02-30T12:00:00Z",
    "2026-09-28T24:00:00Z",
    "2026-09-28T23:59:60Z",
    "0001-01-01T00:00:00+01:00",
    "9999-12-31T23:59:59-01:00",
]


@pytest.mark.parametrize("field", ["observed_at", "expires_at"])
@pytest.mark.parametrize("spelling", TIMES_BY_PATTERN + TIMES_BY_CALENDAR)
def test_anything_but_an_rfc_3339_instant_is_refused_in_either_field(field, spelling):
    value = body(**{"observed_at": EARLIER, field: spelling})
    with pytest.raises(EnvelopeError) as caught:
        parse_signal(raw(value))
    assert str(caught.value) == "Invalid envelope"
    if spelling in TIMES_BY_PATTERN:
        assert list(VALIDATOR.iter_errors(value)) != []


# Invisible and control characters: C0, DEL and C1, the soft hyphen, the combining grapheme
# joiner, the Arabic letter mark, the Mongolian vowel separator, zero-width and directional
# marks, line and paragraph separators, embeddings and overrides, the word joiner, invisible
# operators, isolates and the deprecated format controls, the byte order mark, and the
# interlinear annotation controls.
INVISIBLE = {
    "nul": "\x00",
    "newline": "\n",
    "del": "\x7f",
    "nel": "\x85",
    "csi": "\x9b",
    "alm": "\u061c",
    "zwsp": "\u200b",
    "zwj": "\u200d",
    "rlm": "\u200f",
    "line-separator": "\u2028",
    "rlo": "\u202e",
    "word-joiner": "\u2060",
    "rli": "\u2067",
    "pdi": "\u2069",
    "inhibit-swapping": "\u206a",
    "nominal-digits": "\u206f",
    "soft-hyphen": "\u00ad",
    "grapheme-joiner": "\u034f",
    "mongolian-vowel-separator": "\u180e",
    "annotation-anchor": "\ufff9",
    "annotation-separator": "\ufffa",
    "annotation-terminator": "\ufffb",
    "bom": "\ufeff",
}
FREE_TEXT = {
    "provider_id": lambda text: body(subject=subject(provider_id=text)),
    "request_reference": lambda text: body(request_reference=text),
    "evidence_ref": lambda text: body(evidence_ref=text),
    "attribute": lambda text: body(attributes={"note": text}),
}


@pytest.mark.parametrize("where", FREE_TEXT)
@pytest.mark.parametrize("character", INVISIBLE.values(), ids=INVISIBLE.keys())
def test_invisible_and_control_characters_are_refused_in_free_text(where, character):
    value = FREE_TEXT[where](f"device{character}01")
    with pytest.raises(EnvelopeError):
        parse_signal(raw(value))
    assert list(VALIDATOR.iter_errors(value)) != []


@pytest.mark.parametrize("where", FREE_TEXT)
@pytest.mark.parametrize(
    "text",
    [
        "café",
        "\u05e9\u05dc\u05d5\u05dd \u05e2\u05d5\u05dc\u05dd",
        "Ünïcödé 東京",
        "\U0001f600" * 128,
    ],
    ids=["latin", "hebrew", "mixed", "emoji-at-the-shortest-limit"],
)
def test_visible_text_in_any_script_is_accepted(where, text):
    value = FREE_TEXT[where](text)
    parse_signal(json.dumps(value, ensure_ascii=False).encode())
    assert list(VALIDATOR.iter_errors(value)) == []


@pytest.mark.parametrize(
    "account",
    [
        "urn:uuid:00000000-0000-0000-0000-00000000000a",
        "{00000000-0000-0000-0000-00000000000a}",
        "0000000000000000000000000000000a",
        "00000000-0000-0000-0000-00000000000A",
        "00000000-0000-0000-0000-00000000000",
        10,
    ],
)
def test_an_account_is_only_its_canonical_uuid_spelling(account):
    value = body(subject=subject(account_id=account))
    with pytest.raises(EnvelopeError):
        parse_signal(raw(value))
    assert list(VALIDATOR.iter_errors(value)) != []


@pytest.mark.parametrize(
    "payload",
    [
        b'{"schema_version": "execbound.security-signal.v1", "schema_version": "x"}',
        # A repeated key in an otherwise valid envelope: a parser keeping the last value
        # would read High where a parser keeping the first would read Medium.
        raw(body())[:-1] + b', "verdict": "High"}',
        raw(body()).replace(b"1000", b"NaN"),
        raw(body()).replace(b"1000", b"1000.0"),
        raw(body()).replace(b"1000", b"1e3"),
        raw(body(attributes={"score": 0.5})),
        raw(body(confidence=True)),
        raw(body(confidence="1000")),
        raw(body(confidence=1001)),
        raw(body(schema_version="execbound.security-signal.v2")),
        raw(body(extra="field")),
        raw({key: value for key, value in body().items() if key != "verdict"}),
        raw(body(attributes={f"a{index}": index for index in range(17)})),
        raw(body(attributes={"note": "x" * 255})),
        raw(body(attributes={"nested": {"a": 1}})),
        raw(body(attributes={"Bad-Name": 1})),
        raw(body(attributes={"big": LONG_MAX + 1})),
        raw(body(attributes={"small": LONG_MIN - 1})),
        raw(body(capability="content_integrity.v1")),
        raw(body(subject=subject(kind="run"))),
        raw(body(evidence_digest="A" * 64)),
        raw(body(source_event_id="has space")),
        raw(body(producer={"name": "execbound-mde-producer", "version": "0.1"})),
        # A verdict never starts or ends with whitespace (resolution's `Verdict`).
        raw(body(verdict=" High")),
        raw(body(verdict="High ")),
        raw(body(verdict="x" * 65)),
        # A lone surrogate, escaped, is no character at all.
        raw(body(subject=subject(provider_id="\ud800"))),
        raw(body(attributes={"note": "\udfff"})),
        # `expires_at` may shorten the window, never close it before it opens.
        raw(body(expires_at="2026-09-28T12:00:00+00:00")),
        raw(body(expires_at="2026-09-28T13:00:00+01:00")),
        raw(body(expires_at="2026-09-28T11:59:59+00:00")),
        # Deep nesting inside the bound: pydantic's own depth limit refuses it on Python 3.13,
        # whose standard parser does not exhaust the stack at this depth. The parser still
        # catches RecursionError for an interpreter whose parser would.
        raw(body())[:-1] + b', "attributes": {"deep": ' + b"[" * 3000 + b"]" * 3000 + b"}}",
        raw([body()]),
        b"\xff\xfe" + json.dumps(body()).encode("utf-16-le"),
        b"\xef\xbb\xbf" + raw(body()),
        b"not json",
    ],
)
def test_anything_else_is_refused(payload):
    with pytest.raises(EnvelopeError) as caught:
        parse_signal(payload)
    assert str(caught.value) == "Invalid envelope"


@pytest.mark.parametrize(
    "value",
    [raw(body()).decode(), bytearray(raw(body())), memoryview(raw(body()))],
    ids=["str", "bytearray", "memoryview"],
)
def test_only_bytes_are_parsed(value):
    with pytest.raises(EnvelopeError):
        parse_signal(value)


def test_the_bound_is_eight_kibibytes():
    filler = "x" * 254
    large = body(attributes={f"a{index}": filler for index in range(16)})
    padded = raw(large)
    assert len(padded) < MAX_ENVELOPE_BYTES
    parse_signal(padded)
    with pytest.raises(EnvelopeError):
        parse_signal(padded + b" " * (MAX_ENVELOPE_BYTES - len(padded) + 1))


def test_the_bound_counts_bytes_and_includes_its_last_one():
    base = raw(body())
    exact = base + b" " * (MAX_ENVELOPE_BYTES - len(base))
    assert len(exact) == MAX_ENVELOPE_BYTES
    parse_signal(exact)
    with pytest.raises(EnvelopeError):
        parse_signal(exact + b" ")
    # Over the bound in bytes while well under it in characters.
    wide = json.dumps(
        body(attributes={f"a{index}": "é" * 254 for index in range(16)}), ensure_ascii=False
    ).encode()
    assert len(wide) > MAX_ENVELOPE_BYTES > len(wide.decode())
    SecuritySignal.model_validate_json(wide)
    with pytest.raises(EnvelopeError):
        parse_signal(wide)


# The widest envelopes the parser accepts. tests/test_signal_admit.py sends each through the
# fenced writer; here each is parsed alone, so a bound drawn one short is caught without a
# database.
LONGEST_PRODUCER = "p" + "a0_.-" * 12 + "abc"


def bounds(now: datetime) -> list[dict[str, object]]:
    """The narrowest envelope, the widest text in several scripts, and attributes at their
    limits, all under the longest producer name."""
    oldest = now - timedelta(seconds=3599)
    producer = {"name": LONGEST_PRODUCER}
    return [
        body(
            source_event_id="a",
            producer={**producer, "version": "0.0.0"},
            verdict="M",
            confidence=0,
            subject=subject(resource_type="r", provider_id="d"),
            observed_at=now.isoformat(),
        ),
        body(
            source_event_id="Az09._:-" * 16,
            producer={**producer, "version": "999999.999999.999999"},
            verdict="V" + ("a :_.-0" * 9)[:62] + "Z",
            confidence=1000,
            severity=(" Sev:_.-9" * 4)[:32],
            subject=subject(
                resource_type="r" + "a0_" * 21, provider_id=("\U0001f600é\u05e9" * 43)[:128]
            ),
            action="a" + ("b0_.-" * 16)[:79],
            request_reference="ü\u05e2\u05d1\u05e8\u05d9\u05ea" * 33 + "üü",
            observed_at=oldest.astimezone(timezone(timedelta(hours=5, minutes=30))).isoformat(),
            expires_at=(oldest + timedelta(microseconds=1)).isoformat(),
            evidence_ref="\U0001d11e" * 256,
            evidence_digest="f" * 64,
        ),
        body(
            source_event_id="attributes:at-the-bound",
            producer={**producer, "version": "0.1.0"},
            observed_at=now.isoformat(),
            attributes={
                "a" + "b0_" * 20 + "cd": "\U0001f600" * 254,
                "empty": "",
                "smallest": LONG_MIN,
                "largest": LONG_MAX,
                "yes": True,
                "no": False,
                "zero": 0,
                **{f"n{index}": index for index in range(9)},
            },
        ),
    ]


def test_every_edge_of_every_field_is_accepted_as_sent():
    for value in bounds(AT):
        payload = json.dumps(value, ensure_ascii=False).encode()
        assert len(payload) <= MAX_ENVELOPE_BYTES
        assert list(VALIDATOR.iter_errors(value)) == []
        signal = parse_signal(payload)
        times = ("observed_at", "expires_at")
        sent = {"attributes": {}, **{key: item for key, item in value.items() if key not in times}}
        assert signal.model_dump(mode="json", exclude_none=True, exclude=set(times)) == sent
        for name in times:
            if name in value:
                assert getattr(signal, name) == datetime.fromisoformat(str(value[name]))


def test_the_module_imports_only_the_standard_library_and_pydantic():
    # The definition, in the protocol package since #496; the module this file
    # imports by its old path re-exports it.
    tree = ast.parse(Path(protocol_signals.__file__).read_text(encoding="utf-8"))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom):
            roots.add((node.module or "").split(".")[0])
    assert roots <= {
        "__future__",
        "datetime",
        "hashlib",
        "json",
        "re",
        "typing",
        "uuid",
        "pydantic",
    }


def test_the_published_schema_is_the_models():
    assert json.loads(SCHEMA.read_text(encoding="utf-8")) == SecuritySignal.model_json_schema()


def test_the_published_schema_refuses_attribute_names_the_parser_refuses():
    """A producer validating against the schema meets the parser's attribute names."""
    assert list(VALIDATOR.iter_errors(body(**OPTIONAL))) == []
    for name in ("Bad-Name", "9lives", "a" * 64):
        assert list(VALIDATOR.iter_errors(body(attributes={name: 1}))) != [], name
        with pytest.raises(EnvelopeError):
            parse_signal(raw(body(attributes={name: 1})))


def test_the_schema_describes_what_it_cannot_express():
    description = " ".join(SecuritySignal.model_json_schema()["description"].split())
    for rule in ("UTF-8", "byte order mark", "8,192 bytes", "repeats a key", "fraction"):
        assert rule in description, rule


def test_the_published_schema_says_the_intake_refuses_a_request_reference():
    """The envelope parses `request_reference`, and the intake refuses any envelope carrying one
    (`tests/test_signal_intake.py`); a producer reading only the schema learns that first."""
    published = json.loads(SCHEMA.read_text(encoding="utf-8"))
    field = published["properties"]["request_reference"]
    description = " ".join(field.get("description", "").split())
    for words in ("resource_compromise.v1", "INVALID_ENVELOPE"):
        assert words in description, words
