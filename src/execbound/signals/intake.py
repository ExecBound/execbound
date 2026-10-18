# SPDX-License-Identifier: AGPL-3.0-only
"""The runtime side of admission: find the fence from the token, then call the writer.

Nothing here authenticates. The token's shape names a tenant and a source, the tenant fences
the transaction, and `signal_admit` compares the digest and checks every field inside it. A
refusal is answered with its code; an authentication failure is also counted.
"""

import json
from typing import Any, cast
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from execbound.db import Database, UnsafeDatabaseRole, check_runtime
from execbound.identity import AuthenticationFailed, Reason
from execbound.resolution.models import Clock, SystemClock
from execbound.secrets import find_secrets
from execbound.signals.envelope import SecuritySignal, record_digest
from execbound.signals.tokens import SignalTokenError, digest, selectors

REFUSALS = frozenset(
    {
        "SOURCE_RATE_LIMIT",
        "CONFLICTING_DUPLICATE",
        "CAPABILITY_REFUSED",
        "SUBJECT_REFUSED",
        "INCOMPATIBLE_PRODUCER",
        "FUTURE_OBSERVATION",
        "STALE_ON_ARRIVAL",
        "INVALID_SIGNAL",
        "INVALID_SUBJECT",
        "SOURCE_CAPACITY",
    }
)

# The reasons `signal_admit` gives for a caller that named a real source. Anything else,
# `UNKNOWN` included, is recorded without attribution, as a source nobody could name.
ATTRIBUTED: frozenset[Reason] = frozenset({"MISMATCH", "REVOKED", "EXPIRED", "INACTIVE"})

ADMIT = text(
    "SELECT execbound.signal_admit(:source, :token_hash, :now, :event_id, :record_digest, "
    ":producer_name, :producer_version, :capability, :verdict, :confidence, :severity, "
    ":subject_kind, :subject_account, :subject_provider, :subject_resource_type, "
    ":subject_provider_id, :action, :request_reference, :observed_at, :expires_at, "
    "CAST(:attributes AS jsonb), :evidence_ref, :evidence_digest)"
)


# The status each refusal of a producer is answered with; every other code is 400. A producer
# is answered with its own code: it owns the source, and a refusal it cannot read is a refusal
# it cannot fix. Authentication failures say nothing more.
SIGNAL_STATUS = {
    "INVALID_SOURCE": 401,
    "CAPABILITY_REFUSED": 403,
    "SUBJECT_REFUSED": 403,
    "INCOMPATIBLE_PRODUCER": 403,
    "INVALID_SUBJECT": 403,
    "CONFLICTING_DUPLICATE": 409,
    "SOURCE_RATE_LIMIT": 429,
    "SOURCE_CAPACITY": 429,
    "SIGNAL_UNAVAILABLE": 503,
}


class SignalError(ValueError):
    """A safe code; `failure` is set when the refusal is an authentication failure."""

    def __init__(
        self,
        code: str = "SIGNAL_UNAVAILABLE",
        *,
        failure: AuthenticationFailed | None = None,
        source_id: UUID | None = None,
    ) -> None:
        self.code = code
        self.failure = failure
        self.source_id = source_id
        super().__init__("Signal refused")


def admit_signal(
    db: Database, token: str, signal: SecuritySignal, clock: Clock | None = None
) -> dict[str, Any]:
    # The secret screen is the intake's, not the envelope's: the envelope stays self-contained
    # protocol code. A producer's text is frozen into plans and carried in audit events,
    # and one the export guard would flag would make the tenant's export refuse that window for
    # good. It runs before the token is read and before the writer is called, so, like any
    # other malformed envelope, it is recorded against neither the source's rate nor its
    # health, and it never quotes what it found.
    if find_secrets(signal.model_dump(mode="json"), limit=1):
        raise SignalError("INVALID_ENVELOPE")
    # A capability rule, not the envelope's: the published schema carries `request_reference`,
    # but `resource_compromise.v1`, the only capability, takes no request-scoped record. A
    # request's `reference` is the agent's own string, so a record scoped by it would apply to
    # whichever agent named it, and resolution reads only unscoped records. Refused here, like
    # the secret screen, rather than stored as a record that could never apply. A request-scoped
    # capability will need a binding the agent does not choose.
    if signal.request_reference is not None:
        raise SignalError("INVALID_ENVELOPE")
    try:
        tenant, source = selectors(token)
    except SignalTokenError:
        raise SignalError("INVALID_SOURCE", failure=AuthenticationFailed()) from None
    now = (clock or SystemClock()).now()
    subject = signal.subject
    params = {
        "source": source,
        "token_hash": digest(token),
        "now": now,
        "event_id": signal.source_event_id,
        "record_digest": record_digest(signal),
        "producer_name": signal.producer.name,
        "producer_version": signal.producer.version,
        "capability": signal.capability,
        "verdict": signal.verdict,
        "confidence": signal.confidence,
        "severity": signal.severity,
        "subject_kind": subject.kind,
        "subject_account": subject.account_id,
        "subject_provider": subject.provider,
        "subject_resource_type": subject.resource_type,
        "subject_provider_id": subject.provider_id,
        "action": signal.action,
        "request_reference": signal.request_reference,
        "observed_at": signal.observed_at,
        "expires_at": signal.expires_at,
        "attributes": json.dumps(signal.attributes),
        "evidence_ref": signal.evidence_ref,
        "evidence_digest": signal.evidence_digest,
    }
    try:
        with db.transaction(tenant) as conn:
            check_runtime(conn)
            result: dict[str, Any] = conn.execute(ADMIT, params).scalar_one()
    except (SQLAlchemyError, UnsafeDatabaseRole):
        raise SignalError("SIGNAL_UNAVAILABLE") from None
    refused = result.get("refused")
    if refused == "INVALID_SOURCE":
        reason = result.get("reason")
        failure = (
            AuthenticationFailed(
                reason=cast(Reason, reason),
                tenant_id=tenant,
                subject_kind="source",
                subject_id=source,
            )
            if reason in ATTRIBUTED
            else AuthenticationFailed(reason="UNKNOWN", context_tenant=tenant)
        )
        # The source is named only once the writer found it: anyone who knows a source id
        # could otherwise write refusal lines that name it.
        raise SignalError(
            "INVALID_SOURCE",
            failure=failure,
            source_id=source if reason in ATTRIBUTED else None,
        )
    if refused is not None:
        raise SignalError(
            refused if refused in REFUSALS else "SIGNAL_UNAVAILABLE", source_id=source
        )
    return {
        "source_event_id": signal.source_event_id,
        "received_at": result["received_at"],
        "duplicate": result["duplicate"],
        "source_id": str(source),
    }
