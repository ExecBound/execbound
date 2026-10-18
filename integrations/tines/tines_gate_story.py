# SPDX-License-Identifier: Apache-2.0
"""Generate the importable Tines Gate story, deterministically, from the Execute story.

    uv run python integrations/tines/tines_gate_story.py          # write execbound-gate.json
    uv run python integrations/tines/tines_gate_story.py --check  # fail if it is stale

The decision half is the Execute story's, copied by action name so both stories send the
same wire body and wait the same way. The act half is new: send the grant's provider
command to the vendor with the story's own vendor credential, and report what the vendor
answered at the strongest tier the answer supports. The story never builds a vendor call
from its caller's input, never acts on a re-grant, and never re-sends an effect whose
outcome it does not know.
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
EXECUTE_STORY = ROOT / "integrations/tines/execbound-governed-action.json"
GATE_STORY = ROOT / "integrations/tines/execbound-gate.json"
COPIED = (
    "Entry",
    "Prepare",
    "Has reference?",
    "No reference?",
    "Pending?",
    "Within deadline?",
    "Deadline passed?",
    "Wait",
    "Next attempt",
    "Same key again?",
    "Give up as uncertain?",
    "Unavailable?",
    "Refused?",
    "Transport uncertain?",
)
GRANT = "execute.body.checkpoint.grant"
NOW_ISO = 'DATE(NOW(), "%Y-%m-%dT%H:%M:%S%:z")'
SIGN = (
    '=JWT_SIGN(OBJECT("domain", "execbound.executor.outcome", "version", 1, '
    '"operation_id", grant.binding.operation_id, "account_id", grant.binding.account_id, '
    '"intent_hash", grant.binding.intent_hash, "plan_hash", grant.binding.plan_hash, '
    '"outcome", "FAILED_NOT_EXECUTED", "reason", "CANCELLED_NOT_EXECUTED", '
    f'"reported_at", {NOW_ISO}), CREDENTIAL.execbound_gate_signing, "ES256", '
    'OBJECT("kid", RESOURCE.execbound_gate_key_id))'
)


def guid(name: str) -> str:
    return hashlib.sha256(f"execbound-gate/{name}".encode()).hexdigest()[:32]


def trigger(name: str, *rules: tuple[str, str, str]) -> dict[str, Any]:
    return {
        "name": name,
        "type": "Agents::TriggerAgent",
        "options": {
            "must_match": str(len(rules)),
            "rules": [{"path": path, "type": kind, "value": value} for path, kind, value in rules],
        },
    }


def transform(name: str, payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": name,
        "type": "Agents::EventTransformationAgent",
        "options": {"mode": "message_only", "payload": payload},
    }


def http(
    name: str, url: str, credential: str, payload: str, *, retries: int, retry_on: list[int]
) -> dict[str, Any]:
    return {
        "name": name,
        "type": "Agents::HTTPRequestAgent",
        "options": {
            "disable_redirect_follow": True,
            # Tines' default emits an event for an HTTP error status but none for a timeout
            # or a DNS failure, which stops the run silently. The live trial's lost vendor
            # response did exactly that; with this set a transport failure emits status 0,
            # which every path below classifies.
            "emit_failure_event": True,
            "fail_on_status": False,
            "headers": {
                "Authorization": f"Bearer <<CREDENTIAL.{credential}>>",
                "Content-Type": "application/json",
            },
            "method": "post",
            # JSON text bypasses smart validation's conversion of numeric identifiers.
            "payload": f"=TO_JSON({payload.removeprefix('=')})",
            "retries": retries,
            "retry_on_status": retry_on,
            "url": url,
        },
    }


NEEDS_ADMINISTRATOR = (
    "Stop. Hand this execution to an ExecBound administrator; never resend under a new "
    "reference and never repeat the vendor call."
)
# A settled reference sent again answers 200 with the recorded state and no grant: an
# earlier run called the vendor and reported, and this run did neither.
ALREADY_RECORDED = "This reference already has a recorded result; this run did not call the vendor."
# What `Outcome` says once the gateway accepted a report. An UNKNOWN report is accepted and
# settles nothing (the answer's state is INDETERMINATE), so it is the administrator hand-off
# and not a settlement; otherwise the vendor was either called once or, on the act window
# path, never called at all, and the message says which.
REPORTED_MESSAGE = (
    '=IF(IS_PRESENT(report.status), IF(report.body.state = "INDETERMINATE", '
    f'"{NEEDS_ADMINISTRATOR}", IF(IS_PRESENT(vendor_call.status), '
    '"The vendor was called once and ExecBound settled the report.", '
    '"The vendor was not called: the act window had closed, and ExecBound settled the '
    'signed non-execution.")), SWITCH(DEFAULT(execute.body.state, ""), '
    f'"EXECUTED", "{ALREADY_RECORDED}", "FAILED_NOT_EXECUTED", "{ALREADY_RECORDED}", '
    f'"FAILED_EFFECT_UNKNOWN", "{ALREADY_RECORDED}", "The vendor was not called."))'
)
REPORTED_CODE = (
    '=IF(IS_PRESENT(report.status), IF(report.body.state = "INDETERMINATE", '
    '"VENDOR_OUTCOME_UNKNOWN", DEFAULT(report.body.code, null)), '
    "DEFAULT(execute.body.code, null))"
)


def summary(outcome: str, message: str, code: str) -> dict[str, Any]:
    return {
        "outcome": outcome,
        "path": "gate",
        "state": "=DEFAULT(report.body.state, DEFAULT(execute.body.state, null))",
        # The tier the report settled at, which exists only once the gateway accepted it: a
        # refused report's evidence is still in the story's events and settled nothing.
        "tier": (
            "=IF(DEFAULT(report.status, 0) = 200, "
            "IF(OR(IS_PRESENT(report_journal.body), IS_PRESENT(report_lookup.body)), "
            '"PROVIDER_VERIFIED", IF(IS_PRESENT(report_attestation.body), "ATTESTED", null)), '
            "null)"
        ),
        "execution_id": "=DEFAULT(execute.body.execution_id, null)",
        "request_ref": "=DEFAULT(execute.body.request_ref, null)",
        "approval_state": "=DEFAULT(execute.body.approval_state, null)",
        "approval_url": "=DEFAULT(execute.body.approval_url, null)",
        "vendor_status": "=DEFAULT(vendor_call.status, null)",
        "code": code,
        "reference": "=prepare.reference",
        "message": message,
    }


def build() -> dict[str, Any]:
    execute_story = json.loads(EXECUTE_STORY.read_text())
    source = {agent["name"]: agent for agent in execute_story["agents"]}
    agents: list[dict[str, Any]] = [
        {"name": name, "type": source[name]["type"], "options": source[name]["options"]}
        for name in COPIED
    ]
    execute = source["Execute"]["options"]
    agents += [
        {
            # The Execute story's own request, so the wire body is identical; only the
            # credential differs, because a Gate principal is not an Execute principal.
            "name": "Execute",
            "type": "Agents::HTTPRequestAgent",
            "options": {
                **execute,
                "emit_failure_event": True,
                "headers": {
                    **execute["headers"],
                    "Authorization": "Bearer <<CREDENTIAL.execbound_gate>>",
                },
            },
        },
        transform(
            "Refused: no reference",
            {**source["Refused: no reference"]["options"]["payload"], "path": "gate"},
        ),
        trigger("Final?", ("<<execute.status>>", "regex", "^200$")),
        trigger(
            "Uncertain?",
            ("<<execute.status>>", "regex", "^202$"),
            ("<<execute.body.state>>", "regex", "^INDETERMINATE$"),
        ),
        trigger(
            "Granted?",
            ("<<execute.status>>", "regex", "^202$"),
            ("<<execute.body.state>>", "regex", "^DISPATCH_COMMITTED$"),
            (f"<<{GRANT}.report_secret>>", "regex", "^[A-Za-z0-9_-]{32,}$"),
        ),
        trigger(
            "Regranted?",
            ("<<execute.status>>", "regex", "^202$"),
            ("<<execute.body.state>>", "regex", "^DISPATCH_COMMITTED$"),
            (f"<<{GRANT}.report_secret>>", "!regex", "^[A-Za-z0-9_-]{32,}$"),
        ),
        transform(
            "Grant",
            {
                "execution_id": "=execute.body.execution_id",
                "report_secret": f"={GRANT}.report_secret",
                "binding": f"={GRANT}.binding",
                "provider_operation": f"={GRANT}.provider_operation",
                "provider_command": f"=DEFAULT({GRANT}.provider_command, null)",
                "act_open": f'=IF(GET(DATE_DIFF(NOW(), {GRANT}.act_expires_at), "seconds") > 30, "yes", "no")',  # noqa: E501
                "has_command": f'=IF(IS_PRESENT({GRANT}.provider_command), "yes", "no")',
            },
        ),
        trigger(
            "Act?",
            ("<<grant.act_open>>", "regex", "^yes$"),
            ("<<grant.has_command>>", "regex", "^yes$"),
        ),
        trigger("Act window closed?", ("<<grant.act_open>>", "regex", "^no$")),
        trigger(
            "No provider command?",
            ("<<grant.act_open>>", "regex", "^yes$"),
            ("<<grant.has_command>>", "regex", "^no$"),
        ),
        http(
            "Vendor call",
            "<<RESOURCE.execbound_vendor_origin>>/v1/<<grant.provider_operation>>",
            "execbound_gate_vendor",
            "=grant.provider_command",
            retries=0,
            retry_on=[],
        ),
        trigger("Vendor journal?", ("<<vendor_call.status>>", "regex", "^200$")),
        trigger("Vendor refused?", ("<<vendor_call.status>>", "regex", "^(400|401|403)$")),
        trigger("Vendor conflict?", ("<<vendor_call.status>>", "regex", "^409$")),
        trigger(
            "Vendor uncertain?", ("<<vendor_call.status>>", "!regex", "^(200|400|401|403|409)$")
        ),
        http(
            "Lookup journal",
            "<<RESOURCE.execbound_vendor_origin>>/v1/journal",
            "execbound_gate_vendor",
            "=grant.provider_command",
            retries=3,
            retry_on=[429, 503],
        ),
        trigger("Found?", ("<<lookup_journal.status>>", "regex", "^200$")),
        trigger("Not found?", ("<<lookup_journal.status>>", "!regex", "^200$")),
        transform(
            "Report journal",
            {
                "body": '=OBJECT("report_secret", grant.report_secret, "outcome", IF(vendor_call.body.record.outcome = "EXECUTED", "EXECUTED", "FAILED_NOT_EXECUTED"), "reason", vendor_call.body.record.outcome, "journal", vendor_call.body)'  # noqa: E501
            },
        ),
        transform(
            "Report lookup",
            {
                "body": '=OBJECT("report_secret", grant.report_secret, "outcome", IF(lookup_journal.body.record.outcome = "EXECUTED", "EXECUTED", "FAILED_NOT_EXECUTED"), "reason", lookup_journal.body.record.outcome, "journal", lookup_journal.body)'  # noqa: E501
            },
        ),
        transform("Sign non-execution", {"attestation": SIGN}),
        transform(
            "Report attestation",
            {
                "body": '=OBJECT("report_secret", grant.report_secret, "outcome", "FAILED_NOT_EXECUTED", "reason", "CANCELLED_NOT_EXECUTED", "attestation", sign_non_execution.attestation)'  # noqa: E501
            },
        ),
        transform(
            "Report unknown",
            {
                "body": f'=OBJECT("report_secret", grant.report_secret, "outcome", "UNKNOWN", "reported_at", {NOW_ISO})'  # noqa: E501
            },
        ),
        http(
            "Report",
            "<<RESOURCE.execbound_origin>>/v1/executions/<<grant.execution_id>>/outcome",
            "execbound_gate",
            "=DEFAULT(report_journal.body, DEFAULT(report_lookup.body, DEFAULT(report_attestation.body, report_unknown.body)))",  # noqa: E501
            retries=3,
            retry_on=[429, 500, 502, 503, 504],
        ),
        trigger("Reported?", ("<<report.status>>", "regex", "^200$")),
        trigger("Report refused?", ("<<report.status>>", "!regex", "^200$")),
        transform(
            "Outcome",
            summary(
                '=IF(IS_PRESENT(report.status), IF(report.body.state = "INDETERMINATE", "needs_administrator", "final"), IF(DEFAULT(execute.status, 0) >= 500, "uncertain", SWITCH(DEFAULT(execute.body.state, ""), "PENDING_APPROVAL", "pending", "STALE_AUTHORIZATION", "expired", "INDETERMINATE", "uncertain", "DENIED", "final", "OBSERVED", "final", "EXECUTED", "final", "FAILED_NOT_EXECUTED", "final", "FAILED_EFFECT_UNKNOWN", "uncertain", "refused")))',  # noqa: E501
                REPORTED_MESSAGE,
                REPORTED_CODE,
            ),
        ),
        transform(
            "Needs administrator",
            summary(
                "needs_administrator",
                NEEDS_ADMINISTRATOR,
                '=DEFAULT(report.body.code, IF(IS_PRESENT(report.status), "REPORT_NOT_ACCEPTED", IF(IS_PRESENT(grant.execution_id), "NO_PROVIDER_COMMAND", "REGRANTED_WITHOUT_SECRET")))',  # noqa: E501
            ),
        ),
    ]
    links = [
        ("Entry", "Prepare"),
        ("Prepare", "Has reference?"),
        ("Prepare", "No reference?"),
        ("Has reference?", "Execute"),
        ("No reference?", "Refused: no reference"),
        ("Execute", "Transport uncertain?"),
        ("Execute", "Refused?"),
        ("Execute", "Final?"),
        ("Execute", "Pending?"),
        ("Execute", "Unavailable?"),
        ("Execute", "Uncertain?"),
        ("Execute", "Granted?"),
        ("Execute", "Regranted?"),
        ("Transport uncertain?", "Outcome"),
        ("Refused?", "Outcome"),
        ("Final?", "Outcome"),
        ("Uncertain?", "Outcome"),
        ("Pending?", "Within deadline?"),
        ("Pending?", "Deadline passed?"),
        ("Within deadline?", "Wait"),
        ("Deadline passed?", "Outcome"),
        ("Wait", "Next attempt"),
        ("Next attempt", "Execute"),
        ("Unavailable?", "Same key again?"),
        ("Unavailable?", "Give up as uncertain?"),
        ("Same key again?", "Wait"),
        ("Give up as uncertain?", "Outcome"),
        ("Regranted?", "Needs administrator"),
        ("Granted?", "Grant"),
        ("Grant", "Act?"),
        ("Grant", "Act window closed?"),
        ("Grant", "No provider command?"),
        ("Act window closed?", "Sign non-execution"),
        ("No provider command?", "Needs administrator"),
        ("Act?", "Vendor call"),
        ("Vendor call", "Vendor journal?"),
        ("Vendor call", "Vendor refused?"),
        ("Vendor call", "Vendor conflict?"),
        ("Vendor call", "Vendor uncertain?"),
        ("Vendor journal?", "Report journal"),
        ("Vendor refused?", "Sign non-execution"),
        ("Vendor conflict?", "Report unknown"),
        ("Vendor uncertain?", "Lookup journal"),
        ("Lookup journal", "Found?"),
        ("Lookup journal", "Not found?"),
        ("Found?", "Report lookup"),
        ("Not found?", "Report unknown"),
        ("Sign non-execution", "Report attestation"),
        ("Report journal", "Report"),
        ("Report lookup", "Report"),
        ("Report attestation", "Report"),
        ("Report unknown", "Report"),
        ("Report", "Reported?"),
        ("Report", "Report refused?"),
        ("Reported?", "Outcome"),
        ("Report refused?", "Needs administrator"),
    ]
    names = [agent["name"] for agent in agents]
    index = {name: position for position, name in enumerate(names)}
    exported = []
    for agent in agents:
        exported.append(
            {
                "description": None,
                "disabled": False,
                "guid": guid(agent["name"]),
                "monitoring": None,
                "name": agent["name"],
                "options": agent["options"],
                "origin_story_identifier": "cloud:execbound:gate",
                "reporting": None,
                "template": None,
                "type": agent["type"],
                "width": None,
            }
        )
    exits = ["Outcome", "Needs administrator", "Refused: no reference"]
    story = {
        key: execute_story[key]
        for key in ("schema_version", "standard_lib_version", "action_runtime_version")
    }
    story.update(
        {
            "name": "ExecBound: Gate an action",
            "description": "Ask ExecBound for a decision, act once at your own vendor with your own credential, and report what the vendor answered.",  # noqa: E501
            "guid": guid("story"),
            "slug": "execbound_gate_an_action",
            "agents": exported,
            "links": [{"source": index[a], "receiver": index[b]} for a, b in links],
            "entry_agent_guid": guid("Entry"),
            "exit_agent_guids": [guid(name) for name in exits],
            "api_entry_action_guids": [guid("Entry")],
            "api_exit_action_guids": [guid(name) for name in exits],
            "keep_events_for": 3600,
            # Tines lays the actions out itself from an empty layout. The Execute story's
            # own layout is keyed by that story's action guids, which name nothing here.
            "diagram_layout": "{}",
            "send_to_story_enabled": False,
            "send_to_story_skill_use_requires_confirmation": True,
            "exported_at": "2026-09-23T00:00:00Z",
        }
    )
    for key, value in execute_story.items():
        story.setdefault(key, value if not isinstance(value, (list, dict)) else type(value)())
    return story


def render() -> str:
    return json.dumps(build(), indent=2, sort_keys=True) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    content = render()
    if args.check:
        if GATE_STORY.read_text(encoding="utf-8") != content:
            sys.exit(
                "integrations/tines/execbound-gate.json is stale; "
                "run integrations/tines/tines_gate_story.py"
            )
        return
    GATE_STORY.write_text(content, encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
