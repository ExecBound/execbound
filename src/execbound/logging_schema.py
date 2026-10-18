# SPDX-License-Identifier: AGPL-3.0-only
"""Schema-only JSON application logs: a closed event catalog, fixed fields, no free text.

A record that carries a field outside the schema, an event outside the catalog or text that
matches the replay export's private patterns is replaced by ``log.suppressed``. Logging runs
after outcomes are decided and swallows its own errors, so it can never change a response
or a transaction.
"""

import contextvars
import json
import logging
import sys
from datetime import UTC, datetime
from typing import IO, Any
from uuid import UUID

# The definition the replay export guard also reads. `execbound.secrets` depends on the
# standard library only, so this module still imports nothing from the identity or
# execution packages.
from execbound.secrets import SECRET_TEXT

EVENTS = frozenset(
    {
        # Every HTTP request, a request limit's refusal among them: its status is the 429,
        # and no second line is written for it, so a flood of refusals is not doubled here.
        "request.completed",
        # A first-party plugin loaded or refused (#238); codes and plugin names only.
        "plugins.loaded",
        "plugins.refused",
        # A plugin's sign-in link hidden because its label raised or was not a short line of
        # text (#243); the code and the plugin's name, never the label or the exception.
        "plugins.sign_in_link_failed",
        # The same for a plugin's recovery link on the sign-in page (#678).
        "plugins.recovery_link_failed",
        # A plugin's session feature check that raised, and so did not hold (#496);
        # the feature's name only.
        "plugins.feature_failed",
        "execute.completed",
        "status.completed",
        # What an agent's own space offers it (#545): the count, never an operation name.
        "actions.listed",
        "approval.decided",
        "dispatch.attempted",
        "outcome.recorded",
        "reconciliation.requested",
        "authentication.refused",
        "stop.activated",
        "stop.released",
        "mode.changed",
        "mock.reprovisioned",
        "keys.reloaded",
        "monitor.intake",
        "monitor.processed",
        # Scheduled monitoring (#678): one line per `process --all-tenants` pass and per
        # `collect-due` pass, with counts only, and a collection run that found its lease gone
        # (revoked, or taken by the run after it), with the connection's id.
        "monitor.process_all",
        "monitor.collect_due",
        # A workspace's purge of the directory audit observations no rule reads any more
        # (#355): the workspace and the count, never an observation or an actor.
        "monitor.audit_purged",
        "monitor.lease_lost",
        # `collector-reseal`: one line per pass, with counts only, never a key.
        "monitor.collector_resealed",
        # A refused Microsoft Entra consent callback: the refusal's code and nothing else,
        # never the state, the token, the directory or anything Microsoft sent.
        "monitor.connect_refused",
        # A producer's envelope accepted, and one refused (#478). Never the token or the
        # envelope; the source id, the status or the refusal code.
        "signal.intake",
        "signal.refused",
        # One approval notification's delivery attempt, once settled, and one destination's
        # run of the security event export: identifiers, the resulting state, a count or the
        # attempts, and a code; never a destination's URL or secret.
        "notifications.delivered",
        "export.completed",
        "command.completed",
        "dependency.unavailable",
        "log.suppressed",
        "onboarding.refused",
        "onboarding.claimed",
        "sandbox.reattested",
        "sandbox.expired",
        "sandbox.expiry_refused",
        # A plugin's sandbox lifecycle (#439): a sandbox moved to another plan at the end of
        # its trial, and one whose agents are put to sleep after a long silence.
        "sandbox.fell_back",
        "sandbox.fallback_refused",
        "sandbox.slept",
        "sandbox.sleep_refused",
        # The lifecycle's slots file could not be read, logged rather than silently turning
        # both passes off; and one slot a pass could not read, skipped with a trace.
        "sandbox.slots_unavailable",
        "sandbox.slot_unreadable",
        # A plugin's advance warning of that sleep (#439): warnings queued for one workspace,
        # a workspace whose queueing was refused, and one warning's delivery. The tenant, the
        # warning's id, a count and a code; never an address, a name or a date.
        "dormancy_warning.queued",
        "dormancy_warning.refused",
        "dormancy_warning.delivered",
        "dormancy_warning.skipped",
        "dormancy_warning.failed",
        # A plugin's approval emails to the people who can decide a request (#179): queued (a count
        # per workspace); delivered and skipped (one line per leased message: its id, its approval's
        # id, the state, the code and the attempts); failed in two shapes, one per leased message
        # with those ids, and one for a whole pass that the plugin's scheduled command reports as
        # refused, carrying the operator tenant, the code and the command's name in `command`;
        # refused in four shapes, a workspace's queue by tenant and code, a lease or settle fault
        # with `message_id`, the relay's day unread with `reason` `RELAY_COUNT`, and a one-click
        # stop's database fault with no ids at all; and a subscription ended by its one-click link.
        # Never an address, a link, a secret or a digest.
        "approval_email.queued",
        "approval_email.refused",
        "approval_email.delivered",
        "approval_email.skipped",
        "approval_email.failed",
        "approval_email.unsubscribed",
        "signup.recorded",
        "signup.refused",
        "signup.queued",
        "signup.message",
        "signup.purged",
        "signup.lapsed",
        # Verified Community signup (#243): admission sends a link instead of allocating a
        # seeded slot.
        "signup.verification",
        "signup.provisioned",
        "signup.verify_refused",
        "signup.approved",
        # The hosted service-measures report (#678): one line per run with its state, the
        # count of workspaces visited and its duration, and one per workspace whose read
        # failed, with the workspace's id and the error's class name.
        "measures.run",
        "measures.skipped",
        # Password reset by email (#678): a submission's outcome, a reset email's delivery,
        # a refused link or code, and a completed reset. Codes, a message class and the
        # reset's own id; never an address, its domain, a link, a code or a password.
        "recovery.requested",
        "recovery.message",
        "recovery.refused",
        "recovery.completed",
        "job.skipped",
        # The jobs service (#411). One line per scheduled run, and one for an interval a
        # second replica found taken, which is how the fresh-machine job checks that no
        # interval ran twice.
        "jobs.started",
        "jobs.stopped",
        "job.completed",
        "job.failed",
        "job.timed_out",
        "job.waiting",
        "job.held_elsewhere",
        # A workspace's audit chain that did not verify on the scheduled pass (#154, #159):
        # its code and the sequence where it first failed, never an event's content.
        "audit.chain_failed",
        "mcp.call",
        # Regular sign-in (#429). Both carry the private reason a page never states.
        "sign_in.refused",
        "password.refused",
        # A customer's own identity provider (#177, #241). The refusal carries the private
        # code a page never states; the recheck carries which of its three outcomes the
        # directory gave, which is the only way an operator can see a directory going quiet
        # before sessions start ending.
        "directory.refused",
        "directory.recheck",
        # Teammate invitations (#487): created, delivered, refused and accepted. No address
        # or token is ever a field value here; `invitation_id` is the only identifier.
        "invitation.created",
        "invitation.sent",
        "invitation.refused",
        "invitation.accepted",
        # Sample targets (#420): an install, a removal or a refresh (#545) that wrote rows and
        # its resulting state, never one that found nothing to do, and a refusal with its
        # code, plus a fault's class name as its reason, joined by the fixed code a store's own
        # error carries. None carries a key, a token, a target's facts or an exception's
        # message.
        "samples.installed",
        "samples.removed",
        "samples.refreshed",
        "samples.refused",
        # The weekly summary (#678): delivered, skipped (an empty week, an inactive person,
        # no address), failed, and ended by its one-click link. The tenant, the message id
        # and a code; never an address, a count or the link.
        "weekly_summary.delivered",
        "weekly_summary.skipped",
        "weekly_summary.failed",
        "weekly_summary.unsubscribed",
    }
)
FIELDS = frozenset(
    {
        "ts",
        "level",
        "event",
        "request_id",
        "tenant_id",
        "canonical_target_id",
        "from_version",
        "to_version",
        "principal_id",
        "credential_id",
        "execution_id",
        "operation_id",
        "approval_id",
        "source_id",
        "destination_id",
        "surface",
        "status",
        "state",
        "code",
        "reason",
        "duration_ms",
        "count",
        "attempts",
        "command",
        "exit_code",
        # Where a workspace's audit chain first failed to verify (`audit.chain_failed`).
        "sequence",
        # A scheduled pass's own counts (#678): workspaces visited, those that refused, those
        # its budget did not reach, and connections whose key file the collector does not hold.
        "visited",
        "failed",
        "not_reached",
        "no_key_file",
        # A scheduled collection's Entra delta passes: those that completed, and the rest; and
        # its runs whose read of a directory's audit log was refused, has not caught up, or met
        # the connection's observation bound.
        "delta",
        "delta_failed",
        "audit_failed",
        "audit_backlog",
        "audit_bounded",
        # A monitoring connection's own id (#678), never its label, origin or key.
        "connection_id",
        # The interval a scheduled run belongs to: `floor(now / seconds)`, the number two
        # replicas agree on without talking to each other.
        "tick",
        "key_state",
        "decision",
        "invitation_id",
        # A weekly summary's outbox row (#678); an identifier, never the recipient.
        "message_id",
        "slot",
        # Open sandbox signups (#243). `signup_id` is the request's own id and never the
        # HTTP `request_id` above; `domain` and `free_mail` are what a log line may say
        # about an address, because the address itself never reaches one.
        "signup_id",
        "domain",
        "free_mail",
        "message_class",
        # A password reset's own id (#678): an identifier, never the address it was for.
        "recovery_id",
        "ends_at",
        # How a person proved who they are: `password`, or a configured provider's name.
        # `parameters` names the query keys a provider callback arrived with, never their
        # values, which is what makes a refused callback diagnosable at all.
        "method",
        "parameters",
        # Which of a tenant's providers a line is about. An identifier, never an issuer, a
        # client id, a subject or anything a directory sent.
        "provider_id",
        # A first-party plugin's name: a module name core resolved, never its configuration.
        "plugin",
        # A plugin's session feature, by the name it registered (#496).
        "feature",
        "tool",
        "protocol_version",
        "client_name",
        "client_version",
    }
)
_SCALARS = (str, int, float, bool, type(None), UUID, datetime)
_request_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "execbound_request_id", default=None
)
_HANDLER_MARK = "_execbound_schema_handler"


def set_request_id(value: str | None) -> contextvars.Token[str | None]:
    return _request_id.set(value)


def reset_request_id(token: contextvars.Token[str | None]) -> None:
    _request_id.reset(token)


def current_request_id() -> str | None:
    return _request_id.get()


def _serialize(fields: dict[str, Any]) -> str:
    return json.dumps(fields, sort_keys=True, separators=(",", ":"), default=str)


def _checked(fields: dict[str, Any]) -> tuple[dict[str, Any], str | None]:
    """Return the fields to write and, when suppressed, the reason code."""
    event = fields.get("event")
    if type(event) is not str or event not in EVENTS:
        return {"event": "log.suppressed", "reason": "UNKNOWN_EVENT"}, "UNKNOWN_EVENT"
    if any(type(key) is not str or key not in FIELDS for key in fields):
        return {"event": "log.suppressed", "reason": "UNKNOWN_FIELD"}, "UNKNOWN_FIELD"
    if any(not isinstance(value, _SCALARS) for value in fields.values()):
        return {"event": "log.suppressed", "reason": "UNKNOWN_FIELD"}, "UNKNOWN_FIELD"
    if SECRET_TEXT.search(_serialize(fields)):
        return {"event": "log.suppressed", "reason": "PRIVATE_TEXT"}, "PRIVATE_TEXT"
    return fields, None


class SchemaFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        try:
            raw = getattr(record, "execbound", None)
            fields = dict(raw) if isinstance(raw, dict) else {"event": "log.suppressed"}
            checked, reason = _checked(fields)
            level = "WARNING" if reason is not None else record.levelname
            payload = {
                "ts": datetime.now(UTC).isoformat(),
                "level": level,
                **{
                    k: (str(v) if isinstance(v, UUID | datetime) else v) for k, v in checked.items()
                },
            }
            return _serialize(payload)
        except Exception:
            return '{"event":"log.suppressed","reason":"FORMATTER_FAILED"}'


def capture_handler(stream: IO[str]) -> logging.Handler:
    handler = logging.StreamHandler(stream)
    handler.setFormatter(SchemaFormatter())
    return handler


class StandardErrorHandler(logging.StreamHandler):  # type: ignore[type-arg]
    """Write to whatever standard error *is* now, not whatever it was at install time.

    `install` runs once, and a `StreamHandler` binds the stream it is handed. That is
    invisible in a deployed process, where standard error never changes, and wrong
    everywhere else: pytest replaces and closes its capture stream around every test, so a
    handler installed during one test held a file that was closed before the next one ran,
    and every later record raised inside `emit`. `logging` catches that itself and prints a
    traceback rather than raising, so `log_event`'s own `except` could not see it and a full
    suite emitted 125 of them, which is the noise a real failure has to be found in.

    Resolving the stream per record costs an attribute read and makes the handler mean what
    its name says. A handler built for a named stream, `capture_handler`, still binds that
    stream, because a caller asking for one particular stream means it.
    """

    def __init__(self) -> None:
        super().__init__(sys.stderr)

    def emit(self, record: logging.LogRecord) -> None:
        self.stream = sys.stderr
        super().emit(record)


def install(stream: IO[str] | None = None) -> logging.Logger:
    """Install the standard-error handler once; extra capture handlers are left alone."""
    logger = logging.getLogger("execbound")
    logger.propagate = False
    logger.setLevel(logging.INFO)
    if not any(getattr(h, _HANDLER_MARK, False) for h in logger.handlers):
        handler: logging.Handler = (
            logging.StreamHandler(stream) if stream is not None else StandardErrorHandler()
        )
        handler.setFormatter(SchemaFormatter())
        setattr(handler, _HANDLER_MARK, True)
        logger.addHandler(handler)
    return logger


def log_event(event: str, *, level: str = "INFO", **fields: Any) -> None:
    """Emit one schema record; never raises."""
    try:
        logger = logging.getLogger("execbound")
        if not logger.handlers:
            return
        if logger.level == logging.NOTSET:
            logger.setLevel(logging.INFO)
        payload = {"event": event, **fields}
        if "request_id" not in payload and current_request_id() is not None:
            payload["request_id"] = current_request_id()
        logger.log(logging.getLevelName(level), "", extra={"execbound": payload})
    except Exception:
        return
