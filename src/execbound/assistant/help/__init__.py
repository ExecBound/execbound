# SPDX-License-Identifier: AGPL-3.0-only
"""Help the image can carry: short texts about ExecBound, read by the `help` tool.

The container does not ship `docs/`, so an assistant asked how approvals work cannot read the
guide. These texts are that answer, curated and packaged. Each one summarises a document this
repository holds, and `tests/test_assistant_help.py` holds every text to the document it
summarises by required phrases, so a text cannot drift into saying something the product does
not do. They are facts about the product, never advice about a decision.
"""

from collections.abc import Mapping

SCENARIOS = """ExecBound's sandbox demonstrates six scenarios in order. One, the boundary: an
agent credential opens the agent routes and nothing else, with no human session and no provider
call. Two, three decisions: a workstation with an open critical incident is isolated without a
person, a domain controller is denied, and a production endpoint waits for an approver. Three, a
claim the inventory does not hold is refused before any decision and audited as a rejection.
Four, a shared budget: the same isolation split across two agent credentials until the tenant
total refuses. Five, an agent credential on the approval route is refused and audited. Six, a
stricter policy is previewed against the last 24 hours and the decisions it would have changed
are listed."""

STATES = """An execution is ATTEMPTED when admitted, PENDING_APPROVAL while a person is
required, ELIGIBLE once it may dispatch, and EXECUTED when the provider confirmed the change.
FAILED_NOT_EXECUTED means nothing happened at the provider. FAILED_EFFECT_UNKNOWN means the
attempt is uncertain and an administrator must reconcile it from evidence; it is never retried
or refunded on its own. OBSERVED means the tenant is in observe-only mode and the decision was
recorded without dispatch. DENIED and CANCELLED close a request without an effect."""

OBLIGATIONS = """An obligation is what the policy attached to a decision: most often
APPROVAL_REQUIRED, which means a person of the right scope must decide before the action may
dispatch. Obligations come from the approval set of the active bundle, and a quorum rule may
require more than one approver for the same obligation. An obligation is not a recommendation
and carries no opinion about the action; it names who must decide, not what they should
decide."""

APPROVALS = """An approval is scoped, expiring and consumed once. Only an approver assigned to
that canonical target and action may decide it, the decision is recorded server-side with the
approver's own credential, and one execution claim consumes it. An approval that expires or
whose authority changes is invalidated rather than left usable. The facts an approver reads are
the frozen ones the decision was made on, with their source and observation time."""

BUDGETS = """A limit rule counts distinct targets an agent or a tenant may act on within a
window. The scope says what is counted together: a principal, a tenant, a group, an account or
a selector. When a budget is exceeded the rule either denies the request or requires an
approval, as the rule states. Impact is shared across agents, runs and adapters inside the
configured scope, so two credentials of the same tenant cannot spend the same budget twice."""

CONNECTING = """An agent connects with a credential an administrator issues for an agent
principal, over HTTP at /v1/execute or through the MCP endpoint. The credential opens the agent
routes only: it cannot reach a human page, decide an approval or read another tenant. Every
request names an action, a target and the incident it acts under, and the gateway resolves the
target and freezes the facts before any policy runs."""

TOPICS: Mapping[str, str] = {
    "scenarios": SCENARIOS,
    "states": STATES,
    "obligations": OBLIGATIONS,
    "approvals": APPROVALS,
    "budgets": BUDGETS,
    "connecting": CONNECTING,
}


def text_of(topic: str) -> str:
    """One topic's text as one paragraph, or a KeyError the caller turns into a refusal."""
    return " ".join(TOPICS[topic].split())
