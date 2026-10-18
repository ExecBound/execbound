# SPDX-License-Identifier: AGPL-3.0-only
"""ADMIN policy pages: list, inspect, create, validate, preview, activate and retire bundles.

Every lifecycle step goes through the audited store functions, which recheck the current
ADMIN inside their own transactions; the pages only render and parse.
"""

import json
import re
from datetime import timedelta
from typing import Any
from uuid import UUID, uuid4

from pydantic import ValidationError
from sqlalchemy import text

from execbound.contracts import ContextContract
from execbound.execution import store
from execbound.policy.models import BundleContent, Condition
from execbound.runtime import Runtime
from execbound.surfaces.agents_pages import action_label, limit_usage, window_label
from execbound.surfaces.human import (
    limit_label,
)
from execbound.surfaces.sessions import Session, check_session

MAX_DOCUMENT_BYTES = 512 * 1024
MAX_RULESET_BYTES = 128 * 1024
PREVIEW_WINDOW = timedelta(hours=24)
_PROBLEMS = {
    "INVALID_STATE": ("This bundle's state does not allow that step.", 409),
    "RULESET_MISMATCH": ("The compiled components do not match the rules.", 400),
    "INVALID_COMPONENT": ("A component of the bundle is invalid.", 400),
    "INVALID_BUNDLE": ("The stored content no longer matches its digest.", 409),
    "INVALID_WINDOW": ("The preview window is out of range.", 400),
    "PREVIEW_UNAVAILABLE": ("The preview could not be computed from recent history.", 200),
}


def parse_document(raw: str, tenant: UUID) -> tuple[BundleContent | None, list[str]]:
    """Bundle JSON from the form; problems name field locations, never field values."""
    if len(raw.encode("utf-8")) > MAX_DOCUMENT_BYTES:
        return None, ["document: larger than 512 KB"]
    try:
        value = json.loads(raw)
    except ValueError:
        return None, ["document: not valid JSON"]
    if type(value) is not dict:
        return None, ["document: must be a JSON object"]
    value.setdefault("tenant_id", str(tenant))
    value.setdefault("bundle_id", str(uuid4()))
    if value["tenant_id"] != str(tenant):
        return None, ["tenant_id: must be this tenant"]
    try:
        return BundleContent.model_validate_json(json.dumps(value)), []
    except ValidationError as exc:
        return None, [
            f"{'.'.join(str(part) for part in error['loc']) or '<root>'}: {error['msg']}"
            for error in exc.errors(include_input=False, include_url=False)
        ]
    except (TypeError, ValueError):
        return None, ["document: invalid"]


def _validation_problems(exc: ValidationError, prefix: str = "") -> list[str]:
    return [
        f"{prefix}{'.'.join(str(part) for part in error['loc']) or '<root>'}: {error['msg']}"
        for error in exc.errors(include_input=False, include_url=False)
    ]


def _typed(
    action: str,
    kind: str,
    name: str,
    raw: list[str],
    contracts: dict[str, ContextContract],
    runtime: Runtime,
) -> list[str | int | bool]:
    """Values typed as the declared fact or argument says; an unknown name stays text so the
    compiler refuses it with its location rather than this page inventing a type."""
    cedar_type: str | None = None
    if kind == "fact" and action in contracts:
        fact = next((f for f in contracts[action].facts if f.name == name), None)
        cedar_type = fact.cedar_type if fact else None
    elif kind == "argument":
        try:
            argument = next(
                (a for a in runtime.catalog.actions.action(action).arguments if a.name == name),
                None,
            )
        except Exception:
            argument = None
        cedar_type = argument.cedar_type if argument else None
    typed: list[str | int | bool] = []
    for value in raw:
        if cedar_type == "Long":
            try:
                typed.append(int(value))
            except ValueError:
                raise ValueError(f"{name}: must be a whole number") from None
        elif cedar_type == "Boolean":
            if value.lower() not in ("true", "false"):
                raise ValueError(f"{name}: must be true or false")
            typed.append(value.lower() == "true")
        else:
            typed.append(value)
    return typed


_CONDITION = re.compile(
    r"^(?P<kind>argument\s+)?(?P<name>[a-z][a-z0-9_]{0,62})\s+"
    r"(?P<operator>is one of|is not|is at least|is at most|is)\s+(?P<values>.+?)\s*$"
)
_OPERATORS = {
    "is": "is",
    "is not": "is_not",
    "is one of": "in",
    "is at least": "at_least",
    "is at most": "at_most",
}
_LIMIT = re.compile(r"^(?P<targets>\d{1,18})\s+per\s+(?P<window>\d{1,18})(\s*seconds?|\s*s)?$")


def parse_conditions(
    text: str, action: str, contracts: dict[str, ContextContract], runtime: Runtime
) -> tuple[list[Condition], list[str]]:
    """Conditions written one per line in the words the pages print them in.

    `role is workstation`, `argument reason is false_positive`, `criticality is at least 3`,
    `role is one of server, domain_controller`. The console's form parser takes at most eight
    fields per post, so a rule's conditions travel as one field; the grammar is closed, the
    names are checked against the catalog by the compiler, and the values are typed by the
    declared fact or argument.
    """
    conditions: list[Condition] = []
    problems: list[str] = []
    lines = [line.strip() for line in re.split(r"[\n;]", text) if line.strip()]
    for number, line in enumerate(lines, start=1):
        match = _CONDITION.match(line.lower() if line.lower().startswith("argument ") else line)
        if match is None:
            problems.append(
                f"condition {number}: could not read it; write `name is value`, "
                "`name is not value`, `name is one of a, b`, `name is at least n`, "
                "`name is at most n`, with `argument` first for an argument"
            )
            continue
        kind = "argument" if match.group("kind") else "fact"
        operator = _OPERATORS[match.group("operator")]
        raw = (
            [v.strip() for v in match.group("values").split(",")]
            if operator == "in"
            else [match.group("values").strip()]
        )
        if any(not v for v in raw):
            problems.append(f"condition {number}: a value is empty")
            continue
        try:
            typed = _typed(action, kind, match.group("name"), raw, contracts, runtime)
            conditions.append(
                Condition.model_validate(
                    {
                        "kind": kind,
                        "name": match.group("name"),
                        "operator": operator,
                        "values": tuple(typed),
                    }
                )
            )
        except ValidationError as exc:
            problems += _validation_problems(exc, f"condition {number}.")
        except ValueError as exc:
            problems.append(f"condition {number}: {exc}")
    return conditions, problems


# The console's form parser accepts at most eight fields per post. Each editor step fits
# that exactly, which is why conditions are lines in one field and a ceiling is one field.
RULE_REQUIRED = frozenset({"csrf", "ruleset", "id", "action", "effect"})
RULE_FIELDS = RULE_REQUIRED | frozenset({"quorum", "note", "when"})
BUDGET_REQUIRED = frozenset(
    {"csrf", "ruleset", "rule_id", "action", "scope", "limit", "budget", "on_exceed"}
)
BUDGET_FIELDS = BUDGET_REQUIRED
DRAFT_REQUIRED = frozenset({"csrf", "ruleset"})


# How each limit scope is counted, in the words a page prints beside its meter. The first
# two have one tenant-wide figure and carry one; the rest are counted separately per agent,
# per account or per value of the selected fact, so a single number would not be theirs.
TENANT_WIDE: dict[str, str] = {
    "tenant": "every request in this tenant",
    "group": "every request by a member of this group",
}
PER_QUALIFIER: dict[str, str] = {
    "principal": "each agent on its own",
    "account": "each connector account on its own",
    "selector": "each value of the selected fact on its own",
}


def limit_meters(
    runtime: Runtime, session: Session, content: BundleContent
) -> list[dict[str, Any]]:
    """Every limit rule of one bundle, with the use admission would count against it now.

    The count is admission's own: `agents_pages.limit_usage` is the one statement any meter on
    any page reads, so the Agents page and this one can never come to disagree about the same
    rule. Confirmed and unresolved operations count, and observed ones count only while the
    tenant is in observe mode, exactly as they do for an agent's meters.

    A rule carries a figure only where its scope has one tenant-wide answer. A `principal`
    rule counts each agent on its own and an `account` or `selector` rule narrows on a
    qualifier that statement does not filter, so those carry no number and say how they are
    counted instead of showing one that is not theirs.

    The bundle need not be the active one: a draft's meters say what current use would look
    like against the ceilings it proposes, which is the question an administrator has before
    activating it.
    """
    identity = session.identity
    now = runtime.clock.now()
    rows: list[dict[str, Any]] = []
    with runtime.db.transaction(identity.tenant_id) as conn:
        # The administrator's own check, not the caller's word for it, and the session
        # rechecked inside the fence as every human read does.
        from execbound.policy.store import _policy_identity

        _policy_identity(conn, identity, runtime.clock)
        check_session(conn, session, runtime.clock)
        groups = {
            row.group_id: row.name
            for row in conn.execute(
                text("SELECT group_id, name FROM execbound.principal_groups WHERE tenant_id = :t"),
                {"t": identity.tenant_id},
            )
        }
        observe = store.enforcement_mode(conn, identity.tenant_id) == "OBSERVE"
        for rule in content.limits:
            counted = rule.scope in TENANT_WIDE
            rows.append(
                {
                    "rule": rule,
                    "scope": limit_label(rule, groups),
                    "labels": [action_label(runtime, name) for name in rule.action_names],
                    "window": window_label(rule.window_seconds),
                    "used": limit_usage(
                        conn, identity.tenant_id, None, rule, observe=observe, now=now
                    )
                    if counted
                    else None,
                    "counted": TENANT_WIDE[rule.scope]
                    if counted
                    else PER_QUALIFIER.get(rule.scope, "separately"),
                }
            )
    return rows
