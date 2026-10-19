# SPDX-License-Identifier: AGPL-3.0-only
"""Errors of the console API: a code the client maps to copy, never a diagnostic.

Every refusal is JSON with a `code` from the closed list below and one generic sentence. The
codes are the contract the generated client reads; the sentences exist so a person reading the
network panel is not left with a bare number. Nothing here carries a server string, a
credential, a query or a page's data (#333).
"""

from collections.abc import Mapping

from fastapi import HTTPException
from fastapi.responses import JSONResponse

CODES = {
    "INVALID_REQUEST": (400, "The request was not understood."),
    "INVALID_BODY": (400, "The body has a field that is missing, unknown or out of bounds."),
    "SESSION_REQUIRED": (401, "Sign in to continue."),
    "MFA_REQUIRED": (401, "Verify your identity to continue."),
    # The step-up asked for in place (`step_up.py`): a code that could not be used, whether
    # wrong, already used, or refused while too many attempts have failed.
    "INVALID_FACTOR": (400, "That code could not be used."),
    "FORBIDDEN": (403, "This is not yours to do."),
    "TOKEN_NOT_ALLOWED": (
        403,
        "A personal access token can't do this. Sign in to the console to do it.",
    ),
    "INVALID_CSRF": (403, "The request did not carry the session's token."),
    "INVALID_ORIGIN": (403, "The request came from somewhere else."),
    "INVALID_PRINCIPAL": (400, "That principal cannot be changed from here."),
    "INVALID_BUNDLE": (409, "This bundle's content cannot be used as it stands."),
    "NOT_FOUND": (404, "There is nothing here."),
    "METHOD_NOT_ALLOWED": (405, "This address does not take that method."),
    "CONFLICT": (409, "Something changed first."),
    "WORKSPACE_CHANGED": (409, "The workspace changed. Reload before continuing."),
    "DIRECTORY_REQUIRED": (403, "Use this workspace's organization sign-in to continue."),
    "ALREADY_DECIDED": (409, "Your decision on this approval is already recorded."),
    # "This space takes no new work" is not "this change was already made", and the
    # console's copy has to say which.
    "SPACE_ARCHIVED": (409, "This space takes no new work."),
    "SPACE_REQUIRED": (422, "Choose an active Space before creating this item."),
    # A rules file naming an action this Space serves only through a signal-contract mapping,
    # which a rules file cannot carry, and one whose actions are served by mappings that
    # cannot share one policy: both name the action's location in the file.
    "SIGNAL_MAPPING_ONLY": (400, "An action here is served only by a signal mapping."),
    "MAPPINGS_CONFLICT": (400, "Two mappings for an action here cannot share one policy."),
    "LAST_ADMIN": (409, "Keep at least one active workspace Administrator."),
    "GROUP_IN_USE": (
        409,
        "Remove group members and roles, then disable its approval rules before deleting it.",
    ),
    "APPROVAL_EXPIRED": (409, "This approval has expired; the agent must ask again."),
    "INVALID_CONTINUATION": (
        400,
        "What you are acting on changed since it was read; open it again.",
    ),
    "TOO_LARGE": (413, "The body is too large."),
    "UNSUPPORTED_MEDIA_TYPE": (415, "Send JSON."),
    "STOPPED": (423, "The tenant is stopped."),
    "ASSISTANT_OFF": (409, "The assistant is not turned on for this tenant."),
    "INVALID_PROPOSAL": (409, "The assistant could not draft that rule."),
    "PLAN_LIMIT": (
        409,
        "This workspace has reached its agent limit. Every agent you have keeps running.",
    ),
    # Sample targets (#420). `SAMPLES_NOT_OFFERED` answers an install and a refresh (#545),
    # so its sentence is true of both; the console words each change in its own terms.
    "SAMPLES_NOT_OFFERED": (
        409,
        "Sample targets are added only to a workspace with no policy and no connections of its "
        "own, and are not re-created while a policy depends on them.",
    ),
    "SAMPLES_BUSY": (
        409,
        "A sample request is waiting for approval or provider evidence; settle it first.",
    ),
    "SAMPLES_UNAVAILABLE": (409, "Sample targets are not available on this deployment."),
    # The synthetic directory (#355, step 4): the whole workspace's, added by a workspace
    # administrator only to a workspace that never connected a Microsoft Entra directory; a
    # directory is connected in any Space only once it is removed, and its actors exist nowhere,
    # so none is governed or bound.
    "DIRECTORY_CONNECTED": (
        409,
        "A synthetic directory is added only to a workspace that has never connected Microsoft "
        "Entra.",
    ),
    "SYNTHETIC_DIRECTORY_PRESENT": (
        409,
        "This workspace holds a synthetic directory, which a workspace administrator removes "
        "before Microsoft Entra is connected in any Space.",
    ),
    "SYNTHETIC_ACTOR": (409, "A synthetic directory's actor cannot be governed or bound."),
    "TOO_MANY_REQUESTS": (429, "Too many requests; try again shortly."),
    "UNAVAILABLE": (503, "ExecBound is unavailable; try again shortly."),
    # Teammate invitations (#487): business refusals specific enough to say what
    # happened, rather than the generic `CONFLICT` every other named-conflict code above
    # also avoids.
    "INVITATION_PENDING": (409, "There is already a pending invitation for that address."),
    "ALREADY_MEMBER": (409, "That address already belongs to someone in this workspace."),
    "RESEND_LIMIT": (409, "This invitation cannot be resent again yet."),
    # A principal a re-invitation replaced (0061) is never reactivated: the person is managed
    # through the entry that replaced it.
    "PRINCIPAL_REPLACED": (
        409,
        "This person rejoined through an invitation and now has a new entry in this "
        "workspace. Manage their access there.",
    ),
    # Monitoring connected from the console (#678): a deployment that configured no collector
    # key, a Space that already has a connection for that platform, and a workspace at its
    # cap of connections, revoked ones included.
    "CONNECT_UNAVAILABLE": (409, "Connecting from the console is not set up on this deployment."),
    "CONNECTION_EXISTS": (409, "This Space already has an active connection for that platform."),
    "CONNECTION_CAPACITY": (
        409,
        "This workspace has as many monitoring connections as it can hold.",
    ),
    # Reporting sources: a workspace registers at most 100, revoked ones included, and a story
    # has one unrevoked source in a Space that can still take its events.
    "SOURCE_CAPACITY": (
        409,
        "This workspace has as many reporting sources as it can hold.",
    ),
    "SOURCE_EXISTS": (409, "This Space already has a reporting source for that story."),
    # Microsoft Entra consent: at most five attempts live at once and twenty a day.
    "ATTEMPT_CAPACITY": (429, "Too many connection attempts. Try again later."),
    # Personal access tokens: an owner holds at most ten live tokens.
    "TOO_MANY_TOKENS": (
        409,
        "You already have ten active tokens. Revoke one to create another.",
    ),
}

# The code a status maps to when a refusal carries only its status: a plain HTTPException
# from a guard the pages share, a router refusal, or an execution error answered by status. A
# code a route raises for one named cause never stands in for its whole status, so the
# fallbacks are named here rather than left to whichever code of a status is declared last,
# which once made every bare 409 read "The assistant could not draft that rule."
GENERIC = (
    "INVALID_REQUEST",
    "SESSION_REQUIRED",
    "FORBIDDEN",
    "NOT_FOUND",
    "METHOD_NOT_ALLOWED",
    "CONFLICT",
    "TOO_LARGE",
    "UNSUPPORTED_MEDIA_TYPE",
    "STOPPED",
    "TOO_MANY_REQUESTS",
    "UNAVAILABLE",
)
BY_STATUS = {CODES[code][0]: code for code in GENERIC}


class ApiError(HTTPException):
    """A refusal with its code; `fields` names the locations of an invalid body's faults."""

    def __init__(
        self,
        code: str,
        *,
        fields: list[str] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        status, _ = CODES[code]
        super().__init__(status, headers=dict(headers) if headers is not None else None)
        self.code = code
        self.fields = fields or []


def api_error_response(
    status: int,
    code: str | None = None,
    *,
    fields: list[str] | None = None,
    headers: Mapping[str, str] | None = None,
) -> JSONResponse:
    """The JSON body every console API refusal has."""
    resolved = code if code in CODES else BY_STATUS.get(status, "INVALID_REQUEST")
    body: dict[str, object] = {"code": resolved, "detail": CODES[resolved][1]}
    if fields:
        body["fields"] = fields
    return JSONResponse(body, status_code=status, headers=dict(headers or {}))
