# SPDX-License-Identifier: Apache-2.0
"""Conformance for the executor protocol, version 1: send the vectors, check every answer.

An executor is the service ExecBound dispatches a frozen `ProviderCommand` to and settles on
the signed journal it returns. This module is how anyone building one shows that it keeps the
transaction rules the specification states (`docs/protocol/EXECUTOR_PROTOCOL.md`, section
1.10): for each published vector it sends the vector's command, and the commands derived from
it, and checks each answer the way ExecBound's own connector reads it.

It needs three things from the caller, because no protocol route provisions anything:

- `send`, which posts a body to a path with a bearer credential and returns the answer.
  `http_send` builds one for an executor at an origin; a test can wrap its own client.
- `prepare`, which puts the vector's target at the vector's expected version, in the state the
  vector's transitions start from (`Vector.before`), before each vector is checked.
- An account for the vectors' tenant and account ids, with a dispatch and a control
  credential, signing its journals with a key in the ring the caller names. By default that
  ring is each vector's own public test key, which authenticates nothing anywhere.

`mutations`, when given, reads how many mutations the executor's own store has applied to the
target, and every check also asserts the count; without it, only what the wire shows is
checked, which still catches a mutation that moves the version.

The executor's journal must never have seen the vectors' operations: a vector's operation id is
fixed, so a second run against the same journal is told to start from a fresh one.

What it does not check: the refusals that need a request this `send` cannot shape (a repeated
`Authorization` header, a query string, an identity header, an oversized or malformed body), and
any binding no vector covers. The checkpoint report of chapter 2 is checked by
`execbound_protocol.checkpoint_conformance`, against vectors of its own. Every check raises
`Nonconformance` naming itself, and none is an `assert` statement, so the module checks the
same under `python -O`.

It imports the protocol package and the standard library only, so a vendor can install
`execbound-protocol` and run it without the server.
"""

import hmac
import json
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

from execbound_protocol.canonical import canonical_json
from execbound_protocol.provider import (
    MAX_PROVIDER_BYTES,
    ProviderCommand,
    ProviderError,
    SignedJournal,
    parse_provider,
    signature,
)
from execbound_protocol.strict import _reject_number, _unique_object

JOURNAL = "/v1/journal"
CANCEL = "/v1/cancel"

# Every check, in the order `check` runs them. The specification's conformance table names the
# same ids in the same order, and a test holds the two equal.
CHECKS: tuple[str, ...] = (
    "unknown-lookup",
    "dispatch",
    "repeat",
    "lookup",
    "conflict",
    "version-mismatch",
    "target-not-found",
    "cancel",
    "credentials",
    "follow-up",
)

# The two fields of an executed record the executor chooses itself: when it acted, and the
# version its write produced. Everything else must equal the vector's record exactly.
EXECUTOR_CHOSEN = frozenset({"occurred_at", "resulting_version"})

# A target id no executor provisions, for the target-not-found check.
ABSENT_TARGET = "execbound-conformance-absent-target"


class Nonconformance(AssertionError):
    """An executor answered other than version 1 requires; `check` names which check."""

    def __init__(self, check: str, detail: str) -> None:
        self.check = check
        super().__init__(f"{check}: {detail}")


class VectorError(ValueError):
    """A vector file is malformed, or a vector does not hold together on its own."""


@dataclass(frozen=True)
class Answer:
    """What an executor answered: the status, the two headers ExecBound reads, the body."""

    status: int
    content_type: str
    body: bytes = field(repr=False)
    content_encoding: str = "identity"


# Posts `body` to `path` with `Authorization: Bearer <token>` and returns the answer.
Send = Callable[[str, bytes, str], Answer]


@dataclass(frozen=True)
class Vector:
    """One published conformance vector: a command, the signed journal an executor returned
    for it when the vector was captured, and the public test key that journal verifies under."""

    name: str
    command: ProviderCommand
    signed: SignedJournal
    key_id: str
    key: bytes = field(repr=False)

    @property
    def before(self) -> dict[str, Any] | None:
        """The state the vector's transitions start from, or None when it carries none.

        A record may carry more than one: a password reset records the identity it reset and
        the credential it changed. Their fields are distinct, so the start state is all of
        them in one mapping, and the dispatch check compares every one.
        """
        record = self.signed.record
        state: dict[str, Any] = {}
        for transition in (
            record.identity_transition,
            record.endpoint_transition,
            record.credential_transition,
        ):
            if transition is not None:
                state |= transition.before.model_dump(mode="json")
        return state or None


def _strict(raw: bytes) -> Any:
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_number,
            parse_float=_reject_number,
        )
    except (ValueError, RecursionError):
        raise VectorError("The vector file is not strict JSON") from None


def _vector(name: str, contract: Any, key: bytes) -> Vector:
    try:
        command_canonical = contract["command_canonical"]
        journal_canonical = contract["signed_journal_canonical"]
        command = parse_provider(command_canonical.encode(), ProviderCommand)
        signed = parse_provider(journal_canonical.encode(), SignedJournal)
    except (KeyError, TypeError, AttributeError, ProviderError):
        raise VectorError(f"{name}: not a command and a signed journal") from None
    if canonical_json(command.model_dump(mode="json")) != command_canonical:
        raise VectorError(f"{name}: the command is not in its canonical form")
    if signed.record.command != command:
        raise VectorError(f"{name}: the journal binds another command")
    if not hmac.compare_digest(signed.signature, signature(signed.record, signed.key_id, key)):
        raise VectorError(f"{name}: the journal does not verify under the vector's test key")
    return Vector(name, command, signed, signed.key_id, key)


def load_vectors(raw: bytes) -> tuple[Vector, ...]:
    """Every vector in one published vector file, each checked to hold together.

    A file holds one vector at its top level, as the endpoint contract does, or one per
    action under `actions`, as the identity contract does, beside the public test key
    `test_verification_key_hex`. A vector whose journal does not verify under that key, binds
    another command, or whose command is not in canonical form is refused.
    """
    document = _strict(raw)
    if not isinstance(document, dict):
        raise VectorError("A vector file is a JSON object")
    try:
        key = bytes.fromhex(document["test_verification_key_hex"])
    except (KeyError, TypeError, ValueError):
        raise VectorError("The vector file names no test key") from None
    if "actions" in document:
        actions = document["actions"]
        if not isinstance(actions, dict) or not actions:
            raise VectorError("The vector file's actions are not an object")
        found = tuple(_vector(name, actions[name], key) for name in sorted(actions))
    else:
        single = _vector("vector", document, key)
        found = (replace(single, name=single.command.action),)
    for vector in found:
        if vector.name != vector.command.action:
            raise VectorError(f"{vector.name}: named for another action")
    return found


@dataclass(frozen=True)
class Executor:
    """The executor under test, as the checks reach and observe it."""

    send: Send
    dispatch_token: str = field(repr=False)
    control_token: str = field(repr=False)
    prepare: Callable[[Vector], None]
    # The ring the executor's journals verify under, by key id. None is each vector's own key.
    keys: Mapping[str, bytes] | None = field(default=None, repr=False)
    # How many mutations the executor's store has applied to the vector's target, if it can say.
    mutations: Callable[[Vector], int] | None = None


class _Run:
    """One vector's checks against one executor."""

    def __init__(self, vector: Vector, executor: Executor) -> None:
        self.vector = vector
        self.executor = executor
        self.ring = (
            dict(executor.keys) if executor.keys is not None else {vector.key_id: vector.key}
        )
        self.base = 0

    def derive(self, *, fresh: bool = True, **changes: str) -> ProviderCommand:
        """The vector's command with `changes`, and fresh operation and execution ids unless
        `fresh` is false. Built through the parser, so it is a command version 1 admits."""
        values = self.vector.command.model_dump(mode="json")
        if fresh:
            values |= {"operation_id": str(uuid4()), "execution_id": str(uuid4())}
        values |= changes
        return parse_provider(canonical_json(values).encode(), ProviderCommand)

    def send(self, path: str, command: ProviderCommand, token: str) -> Answer:
        return self.executor.send(path, command.model_dump_json().encode(), token)

    def dispatch(self, command: ProviderCommand, token: str | None = None) -> Answer:
        token = self.executor.dispatch_token if token is None else token
        return self.send("/v1/" + command.provider_operation, command, token)

    def journal(self, check: str, answer: Answer, sent: ProviderCommand) -> SignedJournal:
        """The signed journal an answer carries, read as ExecBound's connector reads it."""
        if answer.status != 200:
            raise Nonconformance(check, f"answered {answer.status}, not 200 with a journal")
        if answer.content_type.split(";")[0] != "application/json":
            raise Nonconformance(check, f"answered with content type {answer.content_type!r}")
        if answer.content_encoding != "identity":
            raise Nonconformance(check, f"answered with encoding {answer.content_encoding!r}")
        if len(answer.body) > MAX_PROVIDER_BYTES:
            raise Nonconformance(check, "answered with a body over the bound")
        try:
            signed = parse_provider(answer.body, SignedJournal)
        except ProviderError:
            raise Nonconformance(
                check, "answered with a body that is not a signed journal"
            ) from None
        key = self.ring.get(signed.key_id)
        if key is None:
            raise Nonconformance(check, f"signed under key id {signed.key_id!r}, outside the ring")
        if not hmac.compare_digest(signed.signature, signature(signed.record, signed.key_id, key)):
            raise Nonconformance(check, "the journal's signature does not verify")
        if signed.record.command != sent:
            raise Nonconformance(check, "the journal binds another command than the one sent")
        return signed

    def refused(self, check: str, answer: Answer, what: str) -> None:
        if answer.status == 200:
            raise Nonconformance(check, f"{what} was answered 200; it must be refused")

    def missing(self, check: str, command: ProviderCommand, what: str) -> None:
        answer = self.send(JOURNAL, command, self.executor.dispatch_token)
        if answer.status != 404:
            raise Nonconformance(check, f"{what}: /v1/journal answered {answer.status}, not 404")

    def mutated(self, check: str, expected: int) -> None:
        if self.executor.mutations is None:
            return
        found = self.executor.mutations(self.vector) - self.base
        if found != expected:
            raise Nonconformance(
                check, f"the target has {found} mutations since it was prepared, not {expected}"
            )

    @staticmethod
    def same(first: SignedJournal, second: SignedJournal) -> bool:
        return canonical_json(first.model_dump(mode="json")) == canonical_json(
            second.model_dump(mode="json")
        )

    def run(self) -> tuple[str, ...]:
        vector, executor = self.vector, self.executor
        command = vector.command
        executor.prepare(vector)
        if executor.mutations is not None:
            self.base = executor.mutations(vector)

        check = "unknown-lookup"
        answer = self.send(JOURNAL, command, executor.dispatch_token)
        if answer.status == 200:
            raise Nonconformance(
                check,
                "/v1/journal already holds the vector's operation; run against a fresh journal",
            )
        if answer.status != 404:
            raise Nonconformance(check, f"/v1/journal answered {answer.status}, not 404")

        check = "dispatch"
        first = self.journal(check, self.dispatch(command), command)
        expected = vector.signed.record.model_dump(mode="json")
        actual = first.record.model_dump(mode="json")
        differing = sorted(
            name
            for name in (expected.keys() | actual.keys()) - EXECUTOR_CHOSEN
            if canonical_json(expected.get(name)) != canonical_json(actual.get(name))
        )
        if differing:
            raise Nonconformance(
                check, "the record differs from the vector's in " + ", ".join(differing)
            )
        produced = first.record.resulting_version
        if produced is None:  # the model refuses an EXECUTED record without one; never reached
            raise Nonconformance(check, "an executed record carries no resulting version")
        self.mutated(check, 1)

        check = "repeat"
        again = self.journal(check, self.dispatch(command), command)
        if not self.same(first, again):
            raise Nonconformance(check, "a repeated command was not answered the retained journal")
        self.mutated(check, 1)

        check = "lookup"
        for token in (executor.dispatch_token, executor.control_token):
            found = self.journal(check, self.send(JOURNAL, command, token), command)
            if not self.same(first, found):
                raise Nonconformance(
                    check, "/v1/journal answered another journal than the retained one"
                )
        self.mutated(check, 1)

        check = "conflict"
        # The same operation id, now at the version the target is actually at: an executor that
        # keyed its journal on anything but the operation would act on it.
        changed = self.derive(fresh=False, expected_version=produced)
        self.refused(
            check, self.dispatch(changed), "a changed command under a retained operation id"
        )
        retained = self.journal(
            check, self.send(JOURNAL, command, executor.dispatch_token), command
        )
        if not self.same(first, retained):
            raise Nonconformance(check, "the retained journal changed after a conflicting command")
        self.mutated(check, 1)

        check = "version-mismatch"
        stale = self.derive()
        record = self.journal(check, self.dispatch(stale), stale).record
        if record.outcome != "VERSION_MISMATCH":
            raise Nonconformance(check, f"a stale command was recorded {record.outcome}")
        if record.resulting_version != produced:
            raise Nonconformance(
                check,
                "VERSION_MISMATCH does not carry the version the first dispatch produced, "
                "so something moved the target after it",
            )
        self.mutated(check, 1)

        check = "target-not-found"
        absent = self.derive(resource_provider_id=ABSENT_TARGET)
        missing = self.journal(check, self.dispatch(absent), absent)
        if missing.record.outcome != "TARGET_NOT_FOUND":
            raise Nonconformance(check, f"an unknown target was recorded {missing.record.outcome}")
        if not self.same(missing, self.journal(check, self.dispatch(absent), absent)):
            raise Nonconformance(check, "TARGET_NOT_FOUND was not retained for its operation")
        self.mutated(check, 1)

        check = "cancel"
        # At the version the target is at, so a dispatch that ignored the tombstone would act.
        cancelled = self.derive(expected_version=produced)
        tombstone = self.journal(
            check, self.send(CANCEL, cancelled, executor.control_token), cancelled
        )
        if tombstone.record.outcome != "CANCELLED_NOT_EXECUTED":
            raise Nonconformance(check, f"a cancellation was recorded {tombstone.record.outcome}")
        late = self.journal(check, self.dispatch(cancelled), cancelled)
        if not self.same(tombstone, late):
            raise Nonconformance(
                check, f"a dispatch after its cancellation was answered {late.record.outcome}"
            )
        after = self.journal(check, self.send(CANCEL, command, executor.control_token), command)
        if not self.same(first, after):
            raise Nonconformance(
                check, "cancelling an executed operation did not answer its journal"
            )
        self.mutated(check, 1)

        check = "credentials"
        wrong = self.derive(expected_version=produced)
        self.refused(
            check,
            self.dispatch(wrong, executor.control_token),
            "a dispatch with the control credential",
        )
        self.missing(check, wrong, "a dispatch with the control credential left a record")
        wrong = self.derive(expected_version=produced)
        self.refused(
            check,
            self.send(CANCEL, wrong, executor.dispatch_token),
            "a cancellation with the dispatch credential",
        )
        self.missing(check, wrong, "a cancellation with the dispatch credential left a record")
        self.mutated(check, 1)

        check = "follow-up"
        follow = self.derive(expected_version=produced)
        record = self.journal(check, self.dispatch(follow), follow).record
        if record.outcome != "EXECUTED":
            raise Nonconformance(
                check,
                f"a command at the version the first dispatch produced was recorded "
                f"{record.outcome}, so something after it moved the target",
            )
        self.mutated(check, 2)
        return CHECKS


def check(vector: Vector, executor: Executor) -> tuple[str, ...]:
    """Run every check for one vector, in order; the ids of the checks it passed."""
    return _Run(vector, executor).run()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """ExecBound's connector follows no redirect, so a redirect is an answer, not a route."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def http_send(origin: str, *, timeout: float = 5.0) -> Send:
    """A `Send` that posts to an executor at `origin` as ExecBound's connector does.

    `origin` is a scheme, a host and an optional port, nothing else. HTTPS certificates are
    verified, no proxy from the environment is used, no redirect is followed and one attempt is
    made per request.
    """
    parsed = urlsplit(origin)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or not 0 < timeout <= 30
    ):
        raise ValueError("Invalid executor origin")
    base = origin.rstrip("/")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())

    def send(path: str, body: bytes, token: str) -> Answer:
        request = urllib.request.Request(  # noqa: S310 - the scheme is checked above
            base + path,
            data=body,
            method="POST",
            headers={
                "Authorization": "Bearer " + token,
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Accept-Encoding": "identity",
            },
        )
        try:
            with opener.open(request, timeout=timeout) as response:
                return Answer(
                    status=response.status,
                    content_type=response.headers.get("Content-Type", ""),
                    content_encoding=response.headers.get("Content-Encoding", "identity"),
                    body=response.read(MAX_PROVIDER_BYTES + 1),
                )
        except urllib.error.HTTPError as error:
            with error:
                return Answer(
                    status=error.code,
                    content_type=error.headers.get("Content-Type", ""),
                    content_encoding=error.headers.get("Content-Encoding", "identity"),
                    body=error.read(MAX_PROVIDER_BYTES + 1),
                )

    return send
