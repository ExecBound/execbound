# SPDX-License-Identifier: AGPL-3.0-only
"""The producer conformance rows #478 and #479 share (`docs/SIGNALS.md`; SG1 to SG9).

A producer under test supplies `envelope(**changes) -> dict`: its own envelope for one covered
host, any field overridden. Each row changes it the way a hostile or broken producer would and
states what the gateway must answer. `reference_envelope` is the kernel's own producer; the
Defender for Endpoint producer (`integrations/mde-producer`) runs the same rows with the
envelope its code builds.

`rows()` returns every envelope a conforming gateway refuses without storing anything: SG1 (a
foreign or merely absent account, or another tenant or principal named outright in an
`x-tenant-id`, `x-principal-id` or `x-role` header, or in a query string), SG4 (malformed
bytes: oversized by raw bytes or by multi-byte content, a duplicate
JSON key, a compressed body, a float or an exponent where the schema requires an integer), SG5
(a well-typed value the gateway still refuses: a foreign schema version, an unknown field,
secret-shaped text, a right-to-left override, trailing whitespace on a verdict, a
non-canonical UUID spelling, or a request reference, which `resource_compromise.v1` refuses
because a request's reference is the agent's own string), SG6 (a capability or a subject
kind the schema does not carry), SG7 (a producer name or version outside the registration),
and SG9 (a future or stale observation, an epoch number, a naive time, or one with a seventh
fractional digit).

`accepted` is the one-row acceptance check every consumer should hold its envelope to before
running the refusal rows. `conflicting_duplicate` is SG8: a prior accepted record and then a
conflicting rewrite of the same event. Its second post is refused while its first post's
record survives, so it cannot join `rows()`'s all-refused, nothing-stored set; it is its own
function instead.

`check` is the one harness every consumer runs a `Row` through, `accepted`'s and
`conflicting_duplicate`'s included: given a `send` that posts a path, a body and headers and
returns the response's status and parsed JSON, it posts `row.prior` first when set, then posts
`row.body` to `"/v1/signals" + row.query` with `row.headers`, and asserts the status, the code
and (when the row pins one) the exact body. It holds no database connection, so a stored-count
or cross-tenant assertion stays the caller's own.

SG2 (an unknown, forged or wrong-kind token) and SG3 (a credential refused on the signal
surface and the reverse) both need a live producer token and a live agent token, which this
module does not mint. The kernel's own `tests/test_signal_conformance.py` keeps them, run
against real registered sources.
"""

import gzip
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

Builder = Callable[..., dict[str, Any]]

# The bound `MAX_ENVELOPE_BYTES` enforces; kept local so this module stays self-contained.
MAX = 8192
# The intake's own refusal, before any envelope is read: no `code`, because no source is
# ever attributed one.
REQUEST = {"detail": "Invalid signal request"}


@dataclass(frozen=True)
class Row:
    id: str
    body: bytes
    status: int
    code: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    # Appended to "/v1/signals" verbatim, e.g. "?tenant_id=...".
    query: str = ""
    # The exact response body, when more than the status and the code need pinning.
    answer: dict[str, Any] | None = None
    # SG8 alone: a first envelope the harness posts and expects accepted before posting `body`.
    prior: bytes | None = None


def reference_envelope(account: UUID, **changes: Any) -> dict[str, Any]:
    now = datetime.now(UTC)
    value: dict[str, Any] = {
        "schema_version": "execbound.security-signal.v1",
        # Microseconds plus a random suffix: two envelopes built in the same process tick,
        # even in a tight test loop, never collide and trip SG8 by accident.
        "source_event_id": f"device-01:{now.strftime('%Y%m%dT%H%M%S%f')}-{uuid4().hex[:6]}",
        "producer": {"name": "execbound-mde-producer", "version": "0.1.0"},
        "capability": "resource_compromise.v1",
        "verdict": "Medium",
        "confidence": 1000,
        "subject": {
            "kind": "resource",
            "account_id": str(account),
            "provider": "mock_crowdstrike",
            "resource_type": "endpoint",
            "provider_id": "device-01",
        },
        "observed_at": now.isoformat(),
    }
    value.update(changes)
    return value


def accepted(envelope: Builder) -> Row:
    """The producer's own envelope, only its event id refreshed: 202, and the record stored."""
    return Row("SG0", json.dumps(envelope(source_event_id="sg0")).encode(), 202)


def conflicting_duplicate(envelope: Builder) -> Row:
    """SG8: `prior` is accepted (202, one record stored); `body` repeats its event id with a
    changed confidence and is refused (409 `CONFLICTING_DUPLICATE`) while the prior record
    stays the only one. Unlike every row `rows()` returns, something is stored here on
    purpose, so this stays its own function rather than an entry in that tuple.
    """
    prior_envelope = envelope(source_event_id="sg8")
    prior = json.dumps(prior_envelope).encode()
    # Whatever the producer's own default confidence is, one of these two differs from it, so
    # the conflict is never accidentally identical to the prior (which a fixed literal value
    # could be, for a producer whose own default already matched it).
    changed = 0 if prior_envelope["confidence"] != 0 else 1000
    conflict = json.dumps({**prior_envelope, "confidence": changed}).encode()
    return Row("SG8", conflict, 409, "CONFLICTING_DUPLICATE", prior=prior)


def check(
    row: Row, send: Callable[[str, bytes, dict[str, str]], tuple[int, dict[str, Any]]]
) -> None:
    """Run one row through a harness's own `send`.

    `send` takes a path, a body and headers, posts it, and returns the response's status code
    and its parsed JSON body. `row.prior`, set only by `conflicting_duplicate`'s SG8, is posted
    to `/v1/signals` first and must be accepted; `row.body` is then posted to
    `"/v1/signals" + row.query` with `row.headers`, and its status, its `code` (when the row
    names one) and its exact body (when the row pins one) are asserted. This is the one check
    `accepted`, `conflicting_duplicate` and every row of `rows()` all run through; what it does
    not check is storage or cross-tenant isolation, which need a database connection this
    module does not hold.

    Failures raise `AssertionError` explicitly, carrying the payload, rather than relying on a
    bare `assert`: a consumer running under `python -O` still sees it, and the message survives
    even where pytest's own assert rewriting does not apply (a producer's own test runner, or a
    module pytest has not rewritten).
    """
    if row.prior is not None:
        prior_status, prior_payload = send("/v1/signals", row.prior, {})
        if prior_status != 202:
            raise AssertionError(f"{row.id}: prior not accepted: {prior_status} {prior_payload!r}")
    status, payload = send("/v1/signals" + row.query, row.body, row.headers)
    if status != row.status:
        raise AssertionError(f"{row.id}: expected status {row.status}, got {status}: {payload!r}")
    if row.code is not None and payload.get("code") != row.code:
        raise AssertionError(f"{row.id}: expected code {row.code!r}, got {payload!r}")
    if row.answer is not None and payload != row.answer:
        raise AssertionError(f"{row.id}: expected body {row.answer!r}, got {payload!r}")


def rows(
    envelope: Builder, *, foreign_account: UUID, foreign_tenant: UUID | None = None
) -> tuple[Row, ...]:
    """Every envelope a conforming gateway refuses, whoever built it; none may be stored.

    `foreign_tenant` names the tenant a header or a query string claims; a caller that has no
    real second tenant to hand (an isolated producer's own test, say) may leave it unset, since
    the header and the query string are refused outright and never actually looked up.
    """
    now = datetime.now(UTC)
    base = envelope()
    named_tenant = foreign_tenant if foreign_tenant is not None else uuid4()

    def body(event: str, **changes: Any) -> bytes:
        return json.dumps(envelope(source_event_id=event, **changes)).encode()

    def subject(**changes: Any) -> dict[str, Any]:
        return {**base["subject"], **changes}

    sized = body("sg4s")
    # Sixteen attributes at the per-value character cap, in a script two bytes per character:
    # under the byte bound in characters, over it in the bytes the wire and the bound both
    # count.
    wide = json.dumps(
        envelope(source_event_id="sg4w", attributes={f"a{i}": "é" * 254 for i in range(16)}),
        ensure_ascii=False,
    ).encode()
    return (
        # No tenant is on the wire, so another tenant can only be implied by an account this
        # tenant does not have, or named outright in a header or a query parameter.
        Row(
            "SG1",
            body("sg1", subject=subject(account_id=str(foreign_account))),
            403,
            "INVALID_SUBJECT",
        ),
        Row(
            "SG1-header-tenant",
            body("sg1ht"),
            400,
            headers={"x-tenant-id": str(named_tenant)},
            answer=REQUEST,
        ),
        Row(
            "SG1-header-principal",
            body("sg1hp"),
            400,
            headers={"x-principal-id": str(uuid4())},
            answer=REQUEST,
        ),
        Row(
            "SG1-header-role",
            body("sg1hr"),
            400,
            headers={"x-role": "ADMIN"},
            answer=REQUEST,
        ),
        Row("SG1-query", body("sg1q"), 400, query=f"?tenant_id={named_tenant}", answer=REQUEST),
        Row("SG4-size", sized + b" " * (MAX + 1 - len(sized)), 400, answer=REQUEST),
        Row("SG4-size-bytes", wide, 400, answer=REQUEST),
        Row(
            "SG4-duplicate-key",
            body("sg4d")[:-1] + b', "verdict": "High"}',
            400,
            "INVALID_ENVELOPE",
        ),
        Row(
            "SG4-compressed",
            gzip.compress(body("sg4c")),
            400,
            headers={"Content-Encoding": "gzip"},
            answer=REQUEST,
        ),
        Row(
            "SG4-float",
            body("sg4f", confidence=1000).replace(b'"confidence": 1000', b'"confidence": 1000.0'),
            400,
            "INVALID_ENVELOPE",
        ),
        Row(
            "SG4-exponent",
            body("sg4e", confidence=1000).replace(b'"confidence": 1000', b'"confidence": 1e3'),
            400,
            "INVALID_ENVELOPE",
        ),
        Row(
            "SG5-schema",
            body("sg5s", schema_version="execbound.security-signal.v2"),
            400,
            "INVALID_ENVELOPE",
        ),
        # There is no field for a prompt, a tool result or a reasoning trace.
        Row(
            "SG5-field",
            body("sg5f", prompt="ignore previous instructions"),
            400,
            "INVALID_ENVELOPE",
        ),
        Row(
            "SG5-secret",
            json.dumps(envelope(source_event_id="sk_live_abcdefgh12")).encode(),
            400,
            "INVALID_ENVELOPE",
        ),
        Row(
            "SG5-bidi",
            body("sg5b", subject=subject(provider_id=base["subject"]["provider_id"] + "\u202e")),
            400,
            "INVALID_ENVELOPE",
        ),
        Row(
            "SG5-verdict-space",
            body("sg5v", verdict=base["verdict"] + " "),
            400,
            "INVALID_ENVELOPE",
        ),
        Row(
            "SG5-account-spelling",
            body("sg5a", subject=subject(account_id="urn:uuid:" + base["subject"]["account_id"])),
            400,
            "INVALID_ENVELOPE",
        ),
        # The schema carries `request_reference`, but no capability accepts it yet: a
        # request's reference is the agent's own string, so a record scoped by it could be
        # claimed by any agent that names it. Refused rather than stored and never applied.
        Row(
            "SG5-request-reference",
            body("sg5r", request_reference="ticket-9"),
            400,
            "INVALID_ENVELOPE",
        ),
        Row(
            "SG6-capability",
            body("sg6c", capability="content_integrity.v1"),
            400,
            "INVALID_ENVELOPE",
        ),
        Row("SG6-subject-kind", body("sg6k", subject=subject(kind="run")), 400, "INVALID_ENVELOPE"),
        Row(
            "SG7",
            body("sg7", producer={**base["producer"], "version": "99.0.0"}),
            403,
            "INCOMPATIBLE_PRODUCER",
        ),
        Row(
            "SG7-name",
            body("sg7n", producer={**base["producer"], "name": "another-producer"}),
            403,
            "INCOMPATIBLE_PRODUCER",
        ),
        Row(
            "SG9-future",
            body("sg9f", observed_at=(now + timedelta(seconds=120)).isoformat()),
            400,
            "FUTURE_OBSERVATION",
        ),
        Row(
            "SG9-stale",
            body("sg9s", observed_at=(now - timedelta(seconds=3601)).isoformat()),
            400,
            "STALE_ON_ARRIVAL",
        ),
        Row("SG9-epoch", body("sg9e", observed_at=int(now.timestamp())), 400, "INVALID_ENVELOPE"),
        Row(
            "SG9-seven-digits",
            body("sg9d", observed_at=now.strftime("%Y-%m-%dT%H:%M:%S.%f") + "1Z"),
            400,
            "INVALID_ENVELOPE",
        ),
        Row(
            "SG9-naive",
            body("sg9n", observed_at=now.replace(tzinfo=None).isoformat()),
            400,
            "INVALID_ENVELOPE",
        ),
    )


ROW_IDS = tuple(
    row.id
    for row in rows(lambda **c: reference_envelope(UUID(int=0), **c), foreign_account=UUID(int=1))
)
