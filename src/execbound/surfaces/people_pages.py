# SPDX-License-Identifier: AGPL-3.0-only
"""People: the humans of a tenant, one list and one page per person, and deprovisioning.

Every write goes through a SECURITY DEFINER function with the 0021 actor check or through
the helpers the credential and approver pages already use, so each fact has one write path.
The page appends the audit events inside the same transaction as the function call, as the
credential pages do, so deactivation is one atomic change across the rows and the chain.
Nothing here deletes a principal; the audit chain refers to people forever.
"""

from datetime import timedelta
from typing import Any
from uuid import UUID, uuid4

from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import DBAPIError

from execbound import directory_store
from execbound.administration import AdministrationError, screened_label
from execbound.audit import acted_with, append_event
from execbound.execution import store
from execbound.operations import PRODUCTION_ACTIONS
from execbound.passwords import normalize_email, reset_code
from execbound.runtime import Runtime
from execbound.secrets import secret_shaped
from execbound.spaces import administered_clause, space_clause, visible_spaces
from execbound.surfaces.admin_pages import (
    _admin,
    _space_to_write,
)
from execbound.surfaces.sessions import Session

HUMAN_KINDS = ("HUMAN_APPROVER", "ADMIN")
STATES = ("active", "deactivated", "all")
LIST_LIMIT = 500
FAILURE_WINDOW = timedelta(hours=24)
# Codes the functions raise, mapped to page copy; never a value from the form.
_PROBLEMS: dict[str, tuple[str, int]] = {
    "INVALID_LABEL": ("A label of 1 to 80 characters is required.", 400),
    "INVALID_REASON": ("A reason of 1 to 500 characters is required.", 400),
    "INVALID_PRINCIPAL": ("That person cannot be changed from here.", 400),
    "INVALID_STATE": ("That person is already in that state.", 409),
    "INVALID_KIND": ("Only approvers can be created here.", 400),
    "INVALID_LIFETIME": ("The lifetime is outside the allowed range.", 400),
    "INVALID_DIGEST": ("The credential could not be prepared.", 503),
    "INVALID_CLOCK": ("The service clock and the database clock disagree.", 503),
    "INVALID_CREDENTIAL": ("That credential is not live, or belongs to an administrator.", 409),
    "INVALID_TARGET": ("That canonical target is not in this tenant.", 400),
    "INVALID_ACTION": ("That action is not in the catalog.", 400),
    "INVALID_SCOPE": ("That assignment is not active.", 409),
    "INVALID_ACTOR": ("Administrator session required.", 403),
    "INVALID_TENANT": ("This tenant is not active.", 403),
    "INVALID_EMAIL": ("A sign-in address is required, and the person must have one.", 400),
    "EMAIL_TAKEN": ("Another person already signs in with that address.", 409),
    "PLAN_LIMIT": (
        "This workspace has reached its agent limit. Every agent you have keeps running.",
        409,
    ),
    # A principal a re-invitation replaced is retired for good (migration 0061).
    "PRINCIPAL_REPLACED": (
        "This person rejoined through an invitation and now has a new entry in this "
        "workspace. Manage their access there.",
        409,
    ),
}
_UNAVAILABLE = ("Administration is unavailable.", 503)


def _call(conn: Connection, statement: str, params: dict[str, Any]) -> Any:
    """Run one definer function; a refusal surfaces as its code and nothing else."""
    try:
        return conn.execute(text(statement), params).scalar_one()
    except DBAPIError as exc:
        diagnostic = getattr(exc.orig, "diag", None)
        message = getattr(diagnostic, "message_primary", None)
        code = message if message in _PROBLEMS else "ADMINISTRATION_UNAVAILABLE"
        raise AdministrationError(code) from None


_PEOPLE = """
SELECT p.principal_id, p.kind, p.active, p.label, p.email, p.number, p.created_at,
       p.deactivated_at, p.replaced_by,
       (SELECT count(*) FROM execbound.credentials c
         WHERE c.tenant_id = p.tenant_id AND c.principal_id = p.principal_id
           AND c.revoked_at IS NULL AND c.expires_at > :now
           AND NOT EXISTS (SELECT 1 FROM execbound.personal_access_tokens k
                            WHERE k.tenant_id = c.tenant_id
                              AND k.credential_id = c.credential_id)) AS live,
       (SELECT count(*) FROM execbound.human_sessions s
         WHERE s.tenant_id = p.tenant_id AND s.principal_id = p.principal_id
           AND s.revoked_at IS NULL AND s.expires_at > :now) AS sessions,
       (SELECT max(s.created_at) FROM execbound.human_sessions s
         WHERE s.tenant_id = p.tenant_id AND s.principal_id = p.principal_id) AS last_sign_in,
       (SELECT count(*) FROM execbound.approval_scopes e
         WHERE e.tenant_id = p.tenant_id AND e.approver_id = p.principal_id
           AND e.active/*space*/) AS scopes
FROM execbound.principals p
WHERE p.tenant_id = :t AND p.kind IN ('HUMAN_APPROVER', 'ADMIN')/*people*/
  AND (CAST(:kind AS text) IS NULL OR p.kind = CAST(:kind AS text))
  AND (CAST(:state AS text) = 'all'
       OR (CAST(:state AS text) = 'active' AND p.active)
       OR (CAST(:state AS text) = 'deactivated' AND NOT p.active))
ORDER BY p.kind, p.label NULLS LAST, p.principal_id
LIMIT :limit
"""

# One person, read under the administration predicate `person_overview` appends.
_PERSON = (
    "SELECT principal_id, kind, active, label, number, created_at, "
    "deactivated_at, replaced_by, email "
    "FROM execbound.principals q WHERE tenant_id = :t AND principal_id = :p "
    "AND kind IN ('HUMAN_APPROVER', 'ADMIN')"
)

_CREDENTIALS = """
SELECT c.credential_id, c.issued_at, c.expires_at, c.revoked_at,
       COALESCE((SELECT sum(f.count) FROM execbound.authentication_failures f
                  WHERE f.tenant_id = c.tenant_id AND f.subject_kind = 'credential'
                    AND f.subject_id = c.credential_id AND f.window_start >= :since), 0)
           AS failures
FROM execbound.credentials c
WHERE c.tenant_id = :t AND c.principal_id = :p
  AND NOT EXISTS (SELECT 1 FROM execbound.personal_access_tokens k
                   WHERE k.tenant_id = c.tenant_id AND k.credential_id = c.credential_id)
ORDER BY c.issued_at DESC, c.credential_id LIMIT :limit
"""

_TARGETS = """
SELECT ct.canonical_target_id,
       string_agg(r.provider_id, ', ' ORDER BY r.provider_id) AS labels
FROM execbound.canonical_targets ct
LEFT JOIN execbound.resource_identities ri
       ON ri.tenant_id = ct.tenant_id AND ri.canonical_target_id = ct.canonical_target_id
LEFT JOIN execbound.resources r
       ON r.tenant_id = ri.tenant_id AND r.account_id = ri.account_id
      AND r.provider = ri.provider AND r.resource_type = ri.resource_type
      AND r.resource_id = ri.resource_id
WHERE ct.tenant_id = :t
GROUP BY ct.canonical_target_id ORDER BY ct.canonical_target_id LIMIT :limit
"""


# History: each table is the person's last twenty rows, newest first.
HISTORY_LIMIT = 20

# The execution is named only where the reader may open its record: outside the reader's
# visible spaces the decision keeps its approval and loses its link (`/*space*/` is the one
# helper's predicate on `e`).
_DECISIONS = """
SELECT d.approval_id, d.decision, d.decided_at, e.canonical_target_id,
       e.frozen -> 'intent' ->> 'action' AS action,
       CASE WHEN TRUE /*space*/ THEN a.execution_id END AS execution_id
FROM execbound.approval_decisions d
JOIN execbound.approvals a ON a.tenant_id = d.tenant_id AND a.approval_id = d.approval_id
JOIN execbound.executions e ON e.tenant_id = a.tenant_id AND e.execution_id = a.execution_id
WHERE d.tenant_id = :t AND d.principal_id = :p
ORDER BY d.decided_at DESC, d.approval_id LIMIT :history
"""

# The event is the record of a sign-in; the session row adds only its device and its state.
_SIGN_INS = """
SELECT a.occurred_at, a.payload ->> 'session_id' AS session_id,
       a.payload ->> 'credential_id' AS credential_id, s.label, s.revoked_at, s.expires_at
FROM execbound.audit_events a
LEFT JOIN execbound.human_sessions s
       ON s.tenant_id = a.tenant_id AND s.principal_id = a.actor_id
      AND CAST(s.session_id AS text) = a.payload ->> 'session_id'
WHERE a.tenant_id = :t AND a.actor_id = :p AND a.kind = 'human_session.issued'
ORDER BY a.sequence DESC LIMIT :history
"""

# Only the identifiers a subject needs leave the database; reasons and hashes never do. A
# session ended for someone else is administration; signing out one's own devices is not.
_ADMINISTRATION = """
SELECT a.occurred_at, a.kind, a.payload ->> 'principal_id' AS principal_id,
       a.payload ->> 'approver_id' AS approver_id, a.payload ->> 'credential_id' AS credential_id,
       a.payload ->> 'bundle_id' AS bundle_id, a.payload ->> 'action' AS action,
       a.payload ->> 'mode' AS mode,
       a.payload ->> 'space_id' AS space_id
FROM execbound.audit_events a
WHERE a.tenant_id = :t AND a.actor_id = :p AND a.kind = ANY(CAST(:kinds AS text[]))
  AND (a.kind <> 'human_session.revoked'
       OR a.payload ->> 'reason' IN ('ADMIN', 'DEACTIVATED'))
ORDER BY a.sequence DESC LIMIT :history
"""

_LABELS = """
SELECT principal_id, label, kind, number FROM execbound.principals
WHERE tenant_id = :t AND principal_id = ANY(CAST(:ids AS uuid[]))
"""

# Every kind the table reads, with the words it is shown as and the payload key that names
# its subject. Anything else in the chain is not an administrative event of a person.
ADMINISTRATIVE: dict[str, tuple[str, str | None]] = {
    "policy.bundle_created": ("Created policy bundle", "bundle_id"),
    "policy.bundle_validated": ("Validated policy bundle", "bundle_id"),
    "policy.bundle_activated": ("Activated policy bundle", "bundle_id"),
    "policy.bundle_retired": ("Retired policy bundle", "bundle_id"),
    "policy.bundle_deselected": ("Deselected policy bundle", "bundle_id"),
    "space.created": ("Created space", "space_id"),
    "space.renamed": ("Renamed space", "space_id"),
    "space.archived": ("Archived space", "space_id"),
    "space.unarchived": ("Unarchived space", "space_id"),
    "space.member_assigned": ("Seated in a space", "principal_id"),
    "space.member_unassigned": ("Removed from a space", "principal_id"),
    "credential.issued": ("Issued credential", "credential_id"),
    "credential.revoked": ("Revoked credential", "credential_id"),
    "approval_scope.assigned": ("Assigned a scope to", "approver_id"),
    "approval_scope.revoked": ("Unassigned a scope from", "approver_id"),
    "principal.created": ("Created", "principal_id"),
    "principal.labelled": ("Labelled", "principal_id"),
    "principal.deactivated": ("Deactivated", "principal_id"),
    "principal.reactivated": ("Reactivated", "principal_id"),
    "agent.bound": ("Bound an agent to", "principal_id"),
    "agent.unbound": ("Unbound an agent from", "principal_id"),
    "human_session.revoked": ("Ended a session of", "principal_id"),
    "tenant.mode_changed": ("Changed the enforcement mode", None),
    "tenant.approval_deadline_changed": ("Changed the approval deadline", None),
    "tenant.stop_activated": ("Activated the emergency stop", None),
    "tenant.stop_released": ("Released the emergency stop", None),
}
_PRINCIPAL_KEYS = ("principal_id", "approver_id")
# What kind of thing an event's subject key names, so a page can link it by its identifier.
SUBJECT_KINDS: dict[str, str] = {
    "bundle_id": "bundle",
    "space_id": "space",
    "credential_id": "credential",
    "principal_id": "principal",
    "approver_id": "principal",
}
_MODES = frozenset({"ENFORCE", "OBSERVE"})


def _parsed(value: object) -> UUID | None:
    """A payload identifier as a UUID, or nothing: a value that is not one is never shown."""
    try:
        return UUID(str(value)) if value is not None else None
    except ValueError:
        return None


def _history(
    conn: Connection, params: dict[str, Any], kind: str, now: Any, session: Session
) -> dict[str, Any]:
    """The person's decisions (approvers), sign-ins, and administrative events (ADMINs)."""
    bounded = {**params, "history": HISTORY_LIMIT}
    decisions = []
    if kind in HUMAN_KINDS:
        space = space_clause(visible_spaces(conn, session), "e")
        statement = _DECISIONS.replace("/*space*/", space.sql)
        for row in conn.execute(
            text(statement),  # nosec B608 - a literal and one helper's predicate; values bound
            {**bounded, **space.params},
        ).mappings():
            decisions.append(
                {
                    "decided_at": row["decided_at"],
                    "approval": str(row["approval_id"])[:8],
                    "approval_id": row["approval_id"],
                    "execution_id": row["execution_id"],
                    "action": row["action"] if row["action"] in PRODUCTION_ACTIONS.names else "",
                    "target": str(row["canonical_target_id"])[:8],
                    "decision": "approved" if row["decision"] == "APPROVE" else "denied",
                }
            )
    sign_ins = []
    for row in conn.execute(text(_SIGN_INS), bounded).mappings():
        session_id, credential_id = _parsed(row["session_id"]), _parsed(row["credential_id"])
        if row["expires_at"] is None:
            state = "ended"
        elif row["revoked_at"] is not None:
            state = "signed out"
        elif row["expires_at"] <= now:
            state = "expired"
        else:
            state = "active"
        sign_ins.append(
            {
                "occurred_at": row["occurred_at"],
                "session": str(session_id)[:8] if session_id else "",
                "credential": str(credential_id)[:8] if credential_id else "",
                "device": row["label"] or "Other",
                "state": state,
            }
        )
    events = []
    if kind == "ADMIN":
        rows = list(
            conn.execute(text(_ADMINISTRATION), {**bounded, "kinds": list(ADMINISTRATIVE)})
            .mappings()
            .all()
        )
        named = {parsed for row in rows for key in _PRINCIPAL_KEYS if (parsed := _parsed(row[key]))}
        facts = {
            row["principal_id"]: row
            for row in conn.execute(
                text(_LABELS), {"t": params["t"], "ids": [str(item) for item in named]}
            ).mappings()
        }
        for row in rows:
            words, key = ADMINISTRATIVE[row["kind"]]
            if row["kind"] == "tenant.mode_changed" and row["mode"] in _MODES:
                words += " to " + row["mode"]
            if row["kind"].startswith("approval_scope.") and (
                row["action"] in PRODUCTION_ACTIONS.names
            ):
                words = words.replace("a scope", row["action"])
            subject = _parsed(row[key]) if key else None
            principal = facts.get(subject) if key in _PRINCIPAL_KEYS else None
            events.append(
                {
                    "occurred_at": row["occurred_at"],
                    "words": words,
                    "subject": str(subject)[:8] if subject else "",
                    "label": principal["label"] if principal is not None else None,
                    # The full identifier and what it names, for a link the router builds;
                    # the server still checks access on the page it opens.
                    "subject_id": subject,
                    "subject_kind": SUBJECT_KINDS[key] if subject and key else None,
                    "subject_principal_kind": principal["kind"] if principal is not None else None,
                    "subject_number": principal["number"] if principal is not None else None,
                }
            )
    return {"decisions": decisions, "sign_ins": sign_ins, "events": events}


def member_factors(conn: Connection, session: Session, people: list[UUID]) -> dict[UUID, bool]:
    """Whether each listed person has an enabled second factor, read as step-up enforcement
    reads it (`admin_member_factors`, 0079): one boolean each, for an active administrator."""
    if not people:
        return {}
    return {
        row["principal_id"]: bool(row["enrolled"])
        for row in conn.execute(
            text(
                "SELECT principal_id, enrolled FROM "
                "execbound.admin_member_factors(:actor, CAST(:ids AS uuid[]))"
            ),
            {"actor": session.identity.principal_id, "ids": [str(item) for item in people]},
        ).mappings()
    }


def people_overview(runtime: Runtime, session: Session, *, state: str, kind: str | None) -> Any:
    """Every human principal matching the filters, with counts as of now."""
    identity = session.identity
    with runtime.db.transaction(identity.tenant_id) as conn:
        _admin(conn, runtime, session)
        # People are members, not owned, so the list is not filtered by the space being
        # looked at; only the scope count follows the spaces the reader can see. Since 0072 an
        # administrator narrowed to spaces is shown only the people they may administer.
        space = space_clause(visible_spaces(conn, session), "e")
        people = administered_clause(conn, session, "p")
        rows = (
            conn.execute(
                text(  # nosec B608 - literals and one helper's predicates only
                    _PEOPLE.replace("/*space*/", space.sql).replace("/*people*/", people.sql)
                ),
                {
                    "t": identity.tenant_id,
                    "now": store.now(runtime.clock),
                    "kind": kind,
                    "state": state,
                    "limit": LIST_LIMIT,
                    **space.params,
                    **people.params,
                },
            )
            .mappings()
            .all()
        )
        factors = member_factors(conn, session, [row["principal_id"] for row in rows])
        _admin(conn, runtime, session)
    return {
        "people": [
            {**dict(row), "second_factor": factors.get(row["principal_id"], False)} for row in rows
        ],
        "state": state,
        "kind": kind,
    }


def person_overview(runtime: Runtime, session: Session, principal: UUID) -> dict[str, Any]:
    """One person's identity, credentials, scopes and sessions; 404 outside the tenant, and
    since 0072 for a person an administrator narrowed to spaces may not administer."""
    identity = session.identity
    with runtime.db.transaction(identity.tenant_id) as conn:
        _admin(conn, runtime, session)
        now = store.now(runtime.clock)
        params: dict[str, Any] = {"t": identity.tenant_id, "p": principal, "limit": LIST_LIMIT}
        people = administered_clause(conn, session, "q")
        person = (
            conn.execute(
                text(_PERSON + people.sql),  # nosec B608 - one helper's predicate; values bound
                {**params, **people.params},
            )
            .mappings()
            .one_or_none()
        )
        if person is None:
            raise HTTPException(404, "Not found")
        credentials = []
        for row in conn.execute(
            text(_CREDENTIALS), {**params, "since": now - FAILURE_WINDOW}
        ).mappings():
            if row["revoked_at"] is not None:
                state = "revoked"
            elif row["expires_at"] <= now:
                state = "expired"
            else:
                state = "live"
            credentials.append({**row, "state": state, "failures": int(row["failures"])})
        scopes: list[dict[str, Any]] = []
        targets: list[dict[str, Any]] = []
        scopes_space = space_clause(visible_spaces(conn, session), "e")
        if person["kind"] in HUMAN_KINDS:
            targets = [dict(row) for row in conn.execute(text(_TARGETS), params).mappings()]
            labels = {row["canonical_target_id"]: row["labels"] for row in targets}
            scopes = [
                {**row, "labels": labels.get(row["canonical_target_id"])}
                for row in conn.execute(
                    text(
                        "SELECT e.canonical_target_id, e.action "
                        "FROM execbound.approval_scopes e "
                        "WHERE e.tenant_id = :t AND e.approver_id = :p AND e.active"
                        + scopes_space.sql  # nosec B608 - one helper's predicate
                        + " ORDER BY e.canonical_target_id, e.action LIMIT :limit"
                    ),
                    {**params, **scopes_space.params},
                ).mappings()
            ]
        sessions = [
            dict(row)
            for row in conn.execute(
                text(
                    "SELECT session_id, created_at, expires_at, label "
                    "FROM execbound.human_sessions WHERE tenant_id = :t AND principal_id = :p "
                    "AND revoked_at IS NULL AND expires_at > :now "
                    "ORDER BY created_at DESC LIMIT :limit"
                ),
                {**params, "now": now},
            ).mappings()
        ]
        # How this person signs in, beside the credentials they hold: whether they carry a
        # password, whether a set-password code is pending, and which directory account is
        # bound to them. All three are facts about the person, and none is a secret: the
        # code's digest and the hash are not read here and no query below selects them.
        sign_in = {
            "account_owned": conn.execute(
                text(
                    "SELECT 1 FROM execbound.workspace_memberships "
                    "WHERE tenant_id=:t AND principal_id=:p"
                ),
                params,
            ).scalar_one_or_none()
            is not None,
            "email": person["email"],
            "has_password": bool(
                conn.execute(
                    text(
                        "SELECT 1 FROM execbound.principal_passwords "
                        "WHERE tenant_id = :t AND principal_id = :p"
                    ),
                    params,
                ).scalar_one_or_none()
            ),
            "pending_until": conn.execute(
                text(
                    "SELECT expires_at FROM execbound.password_resets "
                    "WHERE tenant_id = :t AND principal_id = :p AND redeemed_at IS NULL "
                    "AND revoked_at IS NULL AND expires_at > :now"
                ),
                {**params, "now": now},
            ).scalar_one_or_none(),
            "identities": [
                dict(row)
                for row in conn.execute(
                    text(
                        "SELECT provider, subject, display_name, last_sign_in_at "
                        "FROM execbound.principal_identities "
                        "WHERE tenant_id = :t AND principal_id = :p AND revoked_at IS NULL "
                        "ORDER BY provider LIMIT :limit"
                    ),
                    params,
                ).mappings()
            ],
            # The tenant's own directory beside the deployment's providers (#177, #241): the
            # account this person is bound to, or the invitation that will bind one. Both are
            # facts about the person and neither is a secret; the invitation's digest is not
            # read here and no query above selects it.
            **directory_store.directory_of(conn, identity.tenant_id, principal, now),
        }
        history = _history(conn, params, person["kind"], now, session)
        factors = member_factors(conn, session, [principal])
        _admin(conn, runtime, session)
    return {
        "person": {**dict(person), "second_factor": factors.get(principal, False)},
        "sign_in": sign_in,
        "credentials": credentials,
        "scopes": scopes,
        "targets": targets,
        "actions": sorted(PRODUCTION_ACTIONS.names),
        "sessions": sessions,
        "history": history,
        "history_limit": HISTORY_LIMIT,
        "is_self": person["principal_id"] == identity.principal_id,
    }


def create_approver(runtime: Runtime, session: Session, label: str) -> UUID:
    """A new approver with a label, two functions and two events in one transaction."""
    screened_label(label)
    identity = session.identity
    actor = {"actor": identity.principal_id}
    with runtime.db.transaction(identity.tenant_id) as conn:
        _admin(conn, runtime, session)
        principal = _call(
            conn,
            # A person is a member of spaces, never owned by one: naming a space here
            # seats them in it, exactly as migration 0041 seats every approver that
            # already existed in the tenant's default space.
            "SELECT execbound.admin_create_principal(:actor, :kind, :space)",
            {
                **actor,
                "kind": "HUMAN_APPROVER",
                "space": _space_to_write(conn, session),
            },
        )
        append_event(
            conn,
            identity.tenant_id,
            identity.principal_id,
            "principal.created",
            {
                "principal_id": str(principal),
                "kind": "HUMAN_APPROVER",
                **acted_with(session.identity.credential_id),
            },
        )
        stored = _call(
            conn,
            "SELECT execbound.admin_label_principal(:actor, :principal, :label)",
            {**actor, "principal": principal, "label": label},
        )
        append_event(
            conn,
            identity.tenant_id,
            identity.principal_id,
            "principal.labelled",
            {
                "principal_id": str(principal),
                "label": str(stored),
                **acted_with(session.identity.credential_id),
            },
        )
        _admin(conn, runtime, session)
    return UUID(str(principal))


def label_person(runtime: Runtime, session: Session, principal: UUID, label: str) -> None:
    screened_label(label)
    identity = session.identity
    with runtime.db.transaction(identity.tenant_id) as conn:
        _admin(conn, runtime, session)
        stored = _call(
            conn,
            "SELECT execbound.admin_label_principal(:actor, :principal, :label)",
            {"actor": identity.principal_id, "principal": principal, "label": label},
        )
        append_event(
            conn,
            identity.tenant_id,
            identity.principal_id,
            "principal.labelled",
            {
                "principal_id": str(principal),
                "label": str(stored),
                **acted_with(session.identity.credential_id),
            },
        )
        _admin(conn, runtime, session)


def set_email(runtime: Runtime, session: Session, principal: UUID, email: str) -> str:
    """The address a person signs in with. Refused for an administrator, as 0021 requires."""
    identity = session.identity
    normalized = normalize_email(email)
    if normalized is None:
        raise AdministrationError("INVALID_EMAIL")
    # Only the domain reaches `person.email_set`, so only the domain is screened.
    if secret_shaped(normalized.rsplit("@", 1)[1]):
        raise AdministrationError("INVALID_EMAIL")
    with runtime.db.transaction(identity.tenant_id) as conn:
        _admin(conn, runtime, session)
        stored = _call(
            conn,
            "SELECT execbound.admin_set_email(:actor, :principal, :email)",
            {"actor": identity.principal_id, "principal": principal, "email": normalized},
        )
        append_event(
            conn,
            identity.tenant_id,
            identity.principal_id,
            "person.email_set",
            {
                "principal_id": str(principal),
                # The domain, never the whole address: the chain says which directory a
                # person was pointed at without carrying an address into every export.
                "domain": str(stored).rsplit("@", 1)[1],
                **acted_with(session.identity.credential_id),
            },
        )
        _admin(conn, runtime, session)
    return str(stored)


def password_link(
    runtime: Runtime, session: Session, principal: UUID, lifetime: timedelta
) -> dict[str, Any]:
    """Mint one set-password code for a person, shown once and stored only as its digest.

    The code is not part of any address: what the administrator hands over is the page to
    open and the code to type, which is #241's rule for an invitation and #178's for a
    claim. Minting revokes whatever was pending, so exactly one code ever works.
    """
    identity = session.identity
    reset_id = uuid4()
    code, digest = reset_code(identity.tenant_id, reset_id)
    expires_at = store.now(runtime.clock) + lifetime
    with runtime.db.transaction(identity.tenant_id) as conn:
        _admin(conn, runtime, session)
        _call(
            conn,
            "SELECT execbound.admin_reset_password(:actor, :principal, :reset, :hash, :expires)",
            {
                "actor": identity.principal_id,
                "principal": principal,
                "reset": reset_id,
                "hash": digest,
                "expires": expires_at,
            },
        )
        append_event(
            conn,
            identity.tenant_id,
            identity.principal_id,
            "password.reset_issued",
            {
                "principal_id": str(principal),
                "reset_id": str(reset_id),
                "expires_at": expires_at.isoformat(),
                **acted_with(session.identity.credential_id),
            },
        )
        _admin(conn, runtime, session)
    return {
        "code": code,
        "reset_id": reset_id,
        "principal_id": principal,
        "expires_at": expires_at,
    }


def deactivate(runtime: Runtime, session: Session, principal: UUID, reason: str) -> None:
    """One function call and one event per row it revoked, in one transaction."""
    if secret_shaped(reason):
        raise AdministrationError("INVALID_REASON")
    identity = session.identity
    with runtime.db.transaction(identity.tenant_id) as conn:
        _admin(conn, runtime, session)
        revoked = _call(
            conn,
            "SELECT execbound.admin_deactivate_principal(:actor, :principal, :reason)",
            {"actor": identity.principal_id, "principal": principal, "reason": reason},
        )
        credentials = [str(c) for c in revoked.get("credentials", [])]
        sessions = [str(s) for s in revoked.get("sessions", [])]
        for credential in credentials:
            append_event(
                conn,
                identity.tenant_id,
                identity.principal_id,
                "credential.revoked",
                {
                    "credential_id": credential,
                    "principal_id": str(principal),
                    "reason": "DEACTIVATED",
                    **acted_with(session.identity.credential_id),
                },
            )
        for ended in sessions:
            append_event(
                conn,
                identity.tenant_id,
                identity.principal_id,
                "human_session.revoked",
                {
                    "session_id": ended,
                    "principal_id": str(principal),
                    "reason": "DEACTIVATED",
                    **acted_with(session.identity.credential_id),
                },
            )
        append_event(
            conn,
            identity.tenant_id,
            identity.principal_id,
            "principal.deactivated",
            {
                "principal_id": str(principal),
                "reason": reason,
                "credentials_revoked": len(credentials),
                "sessions_revoked": len(sessions),
                **acted_with(session.identity.credential_id),
            },
        )
        _admin(conn, runtime, session)


def reactivate(runtime: Runtime, session: Session, principal: UUID) -> None:
    identity = session.identity
    with runtime.db.transaction(identity.tenant_id) as conn:
        _admin(conn, runtime, session)
        _call(
            conn,
            "SELECT execbound.admin_reactivate_principal(:actor, :principal)",
            {"actor": identity.principal_id, "principal": principal},
        )
        append_event(
            conn,
            identity.tenant_id,
            identity.principal_id,
            "principal.reactivated",
            {"principal_id": str(principal), **acted_with(session.identity.credential_id)},
        )
        _admin(conn, runtime, session)
