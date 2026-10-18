# SPDX-License-Identifier: Apache-2.0
"""Generate the importable Tines Monitor example story, deterministically.

    uv run python integrations/tines/tines_monitor_story.py          # write execbound-monitor.json
    uv run python integrations/tines/tines_monitor_story.py --check  # fail if it is stale

The story is an example of a story ExecBound monitors rather than governs: it acts at a vendor
with its own credential, then reports what happened to `POST /v1/monitor/events` with a
monitoring source token. ExecBound authorizes nothing here; a report is source-reported
evidence and never settles, approves or limits anything.

The reporting actions are meant to be copied into a builder's own story. They live inside
the acting story, not in a shared reporter story, because a source token is bound to one
story id and coverage matches a discovered story to its source by that id. The story id
comes from `META.story.id`, so copied actions need no edit beyond their credential.

The heartbeat joins the same `Report` action as the result path, which makes the two one
connected flow (Community Edition allows three) and gives both paths the same failure exit.
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
EXECUTE_STORY = ROOT / "integrations/tines/execbound-governed-action.json"
MONITOR_STORY = ROOT / "integrations/tines/execbound-monitor.json"
# The catalog action the example performs. A builder's copy names its own action; an
# operation that cannot be established is reported as `unknown` rather than guessed.
ACTION = "endpoint.isolate"
IDENTIFIER = "^[A-Za-z0-9._:-]{1,96}$"
# Every five minutes: the source's default heartbeat interval is 300 seconds and it reads
# stale after two missed intervals, so one late run does not raise a finding.
HEARTBEAT_CRON = "*/5 * * * *"
STORY_ID = "TEXT(META.story.id)"
# Built from the incoming event's id, which is the example action's own emitted event: a
# re-run of `Build result` on that event rebuilds the same id and the same body, and a new
# attempt of the action is a new event and so a new observation.
RESULT_EVENT_ID = f'APPEND("tines-", {STORY_ID}, "-", TEXT(META.event.id))'
OUTCOME = (
    'IF(DEFAULT(act.status, 0) = 0, "unknown", '
    'IF(AND(act.status >= 200, act.status <= 299), "success", "error"))'
)


def guid(name: str) -> str:
    return hashlib.sha256(f"execbound-monitor/{name}".encode()).hexdigest()[:32]


def trigger(name: str, description: str, *rules: tuple[str, str, str]) -> dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "type": "Agents::TriggerAgent",
        "options": {
            "must_match": str(len(rules)),
            "rules": [{"path": path, "type": kind, "value": value} for path, kind, value in rules],
        },
    }


def transform(
    name: str,
    description: str,
    payload: dict[str, Any],
    *,
    schedule: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    agent: dict[str, Any] = {
        "name": name,
        "description": description,
        "type": "Agents::EventTransformationAgent",
        "options": {"mode": "message_only", "payload": payload},
    }
    if schedule is not None:
        agent["schedule"] = schedule
    return agent


def http(
    name: str,
    description: str,
    url: str,
    credential: str,
    value: str,
    *,
    retries: int,
    retry_on: list[int],
) -> dict[str, Any]:
    """A POST whose body is `value`, a formula producing an object, sent as JSON text.

    There is no `content_type`: with `content_type: json` Tines "smart validates" the payload
    and sends a digit-only string such as a story id as a number, which the intake's strict
    parser refuses. `TO_JSON` and an explicit header send the text exactly as built.
    """
    return {
        "name": name,
        "description": description,
        "type": "Agents::HTTPRequestAgent",
        "options": {
            "disable_redirect_follow": True,
            # Without this a timeout or a DNS failure emits no event and the run stops
            # silently; with it the action emits status 0, which both paths classify.
            "emit_failure_event": True,
            "fail_on_status": False,
            "headers": {
                "Authorization": f"Bearer <<CREDENTIAL.{credential}>>",
                "Content-Type": "application/json",
            },
            "method": "post",
            "payload": f"=TO_JSON({value})",
            "retries": retries,
            "retry_on_status": retry_on,
            "url": url,
        },
    }


def body(**fields: str) -> str:
    """One `OBJECT(...)` formula; every value is already a formula expression."""
    pairs = ", ".join(f'"{key}", {value}' for key, value in fields.items())
    return f"=OBJECT({pairs})"


REPORTED = "DEFAULT(build_result.body, build_heartbeat.body)"


def reported(field: str) -> str:
    return f"=DEFAULT(build_result.body.{field}, build_heartbeat.body.{field})"


def build() -> dict[str, Any]:
    agents: list[dict[str, Any]] = [
        {
            "name": "Entry",
            "description": (
                "Example trigger with a `target`. In your own story this is whatever "
                "already starts the work."
            ),
            "type": "Agents::WebhookAgent",
            "options": {"include_headers": False, "path": "", "secret": "", "verbs": "post"},
        },
        transform(
            "Prepare",
            (
                "Reads the target and stamps when the action is attempted. The stamp is "
                "taken before the action so re-running the report rebuilds the same body."
            ),
            {
                "target": "=DEFAULT(entry.body.target, DEFAULT(entry.target, null))",
                "attempted_at": '=DATE(NOW(), "%Y-%m-%dT%H:%M:%S%:z")',
            },
        ),
        trigger(
            "Has target?",
            "A target ExecBound can record: letters, digits, dot, underscore, colon, hyphen.",
            ("<<prepare.target>>", "regex", IDENTIFIER),
        ),
        http(
            "Act",
            (
                "The example's consequential action, at a vendor, with the story's own "
                "vendor credential. Replace it with yours. Never retried: a second send "
                "could be a second effect."
            ),
            "<<RESOURCE.execbound_lab_vendor_origin>>/v1/isolate",
            "execbound_lab_vendor",
            'OBJECT("target", prepare.target)',
            retries=0,
            retry_on=[],
        ),
        transform(
            "Build result",
            (
                "The observation for the action's result. The outcome is what the vendor "
                "answered: 2xx is success, no answer at all is unknown, anything else is an "
                "error. Report errors as well as successes."
            ),
            {
                "body": body(
                    version="1",
                    event_id=RESULT_EVENT_ID,
                    story_id=STORY_ID,
                    occurred_at="prepare.attempted_at",
                    kind='"tool_result"',
                    action=f'"{ACTION}"',
                    target_ref="prepare.target",
                    outcome=OUTCOME,
                )
            },
        ),
        transform(
            "Heartbeat",
            (
                "Runs every five minutes whether or not anything else happens, so a broken "
                "reporting path shows as a stale source instead of as silence."
            ),
            {
                "minute": '=DATE(NOW(), "%Y%m%dT%H%M")',
                "at": '=DATE(NOW(), "%Y-%m-%dT%H:%M:00+00:00")',
            },
            schedule=[{"cron": HEARTBEAT_CRON, "timezone": "Etc/UTC"}],
        ),
        transform(
            "Build heartbeat",
            "Stamps the heartbeat to the minute. Every accepted send refreshes source freshness.",
            {
                "body": body(
                    version="1",
                    event_id=f'APPEND("hb-", {STORY_ID}, "-", heartbeat.minute)',
                    story_id=STORY_ID,
                    occurred_at="heartbeat.at",
                    kind='"heartbeat"',
                )
            },
        ),
        http(
            "Report",
            (
                "Sends the report with the story's monitoring source token. A tool-result retry "
                "resends the identical body, which ExecBound records once. Heartbeats only "
                "refresh source freshness."
            ),
            "<<RESOURCE.execbound_monitor_origin>>/v1/monitor/events",
            "execbound_monitor_source",
            REPORTED,
            retries=3,
            retry_on=[429, 500, 502, 503, 504],
        ),
        trigger(
            "Recorded?",
            "202 is a new tool result or refreshed heartbeat; 200 is an already recorded result.",
            ("<<report.status>>", "regex", "^(200|202)$"),
        ),
        trigger(
            "Not recorded?",
            "Anything else: ExecBound has not accepted this report.",
            ("<<report.status>>", "!regex", "^(200|202)$"),
        ),
        transform(
            "Reported",
            "Exit: the tool result is recorded or heartbeat freshness is refreshed.",
            {
                "reported": (
                    f'=IF({reported("kind")[1:]} = "heartbeat", "refreshed", '
                    'IF(report.status = 202, "recorded", "duplicate"))'
                ),
                "kind": reported("kind"),
                "event_id": reported("event_id"),
                "observation_id": "=DEFAULT(report.body.observation_id, null)",
            },
        ),
        transform(
            "Reporting failed",
            (
                "Exit: route this to your own alerting. A result that is not recorded is a "
                "gap in what ExecBound can see; `auth_lost` means the source token expired, "
                "was revoked or was rotated past its grace window."
            ),
            {
                "reported": "failed",
                "reason": (
                    '=SWITCH(TEXT(DEFAULT(report.status, 0)), "401", "auth_lost", '
                    '"409", "conflict", "0", "unreachable", "not_recorded")'
                ),
                "status": "=DEFAULT(report.status, 0)",
                "code": "=DEFAULT(report.body.code, null)",
                "kind": reported("kind"),
                "event_id": reported("event_id"),
            },
        ),
    ]
    links = [
        ("Entry", "Prepare"),
        ("Prepare", "Has target?"),
        ("Has target?", "Act"),
        ("Act", "Build result"),
        ("Build result", "Report"),
        ("Heartbeat", "Build heartbeat"),
        ("Build heartbeat", "Report"),
        ("Report", "Recorded?"),
        ("Report", "Not recorded?"),
        ("Recorded?", "Reported"),
        ("Not recorded?", "Reporting failed"),
    ]
    names = [agent["name"] for agent in agents]
    index = {name: position for position, name in enumerate(names)}
    exported = []
    for agent in agents:
        exported.append(
            {
                "description": agent["description"],
                "disabled": False,
                "guid": guid(agent["name"]),
                "monitoring": None,
                "name": agent["name"],
                "options": agent["options"],
                "origin_story_identifier": "cloud:execbound:monitor",
                "reporting": None,
                "schedule": agent.get("schedule"),
                "template": None,
                "type": agent["type"],
                "width": None,
            }
        )
    execute_story = json.loads(EXECUTE_STORY.read_text())
    story = {
        key: execute_story[key]
        for key in ("schema_version", "standard_lib_version", "action_runtime_version")
    }
    story.update(
        {
            "name": "ExecBound: Monitor an action (example)",
            "description": (
                "An example of a story ExecBound monitors: it acts at a vendor with its own "
                "credential and reports each result, and a heartbeat, to ExecBound. Copy "
                "Prepare's stamp, Build result, Heartbeat, Build heartbeat, Report and the "
                "two exits into your own story."
            ),
            "guid": guid("story"),
            "slug": "execbound_monitor_an_action_example",
            "agents": exported,
            "links": [{"source": index[a], "receiver": index[b]} for a, b in links],
            "entry_agent_guid": None,
            "exit_agent_guids": [],
            "api_entry_action_guids": [],
            "api_exit_action_guids": [],
            # A day, so a trial or a first week of instrumentation can be read back.
            "keep_events_for": 86400,
            "diagram_layout": "{}",
            "send_to_story_enabled": False,
            "send_to_story_skill_use_requires_confirmation": True,
            "exported_at": "2026-09-25T00:00:00Z",
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
        if MONITOR_STORY.read_text(encoding="utf-8") != content:
            sys.exit(
                "integrations/tines/execbound-monitor.json is stale; "
                "run integrations/tines/tines_monitor_story.py"
            )
        return
    MONITOR_STORY.write_text(content, encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
