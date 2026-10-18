# SPDX-License-Identifier: AGPL-3.0-only
"""Summarize one security scan run into a retained, secret-free finding population.

Each scanner's own report is retained beside this file. This summary is the evidence a
reviewer reads first: which scanner ran, at which revision, whether it reported anything,
and how many findings it reported. It carries identifiers and counts only — never a secret,
a match, or a source line — so it stays safe to retain for as long as triage needs it.
"""

import argparse
import json
import os
import tomllib
from collections import Counter
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

# A scanner step that did not run at all, as opposed to one that ran and found nothing.
NOT_RUN = {"skipped", "cancelled"}
MAX_REPORT_BYTES = 32 * 1024 * 1024
# What the image scan treats as actionable. An image carries hundreds of advisories that
# nobody can act on: failing on all of them teaches a reader to ignore the run. A high or
# critical advisory whose package has a published fix is something someone can do today.
ACTIONABLE_SEVERITY = {"HIGH", "CRITICAL"}
IMAGE_POLICY = "HIGH or CRITICAL severity with a fixed version published"
IMAGE_REPORT = "local-data/security/trivy.json"
# Advisories accepted for a time, each with a reason and a review date. The file is optional:
# where it does not exist, nothing is acknowledged and every actionable finding stands.
ACKNOWLEDGEMENTS = "security/acknowledged-advisories.toml"
# An acceptance that cannot expire is an exemption. Six months is long enough to wait for an
# upstream rebuild and short enough that the reason has to still be true when it is renewed.
MAX_ACKNOWLEDGEMENT_DAYS = 180
REQUIRED_FIELDS = ("id", "package", "accepted_on", "review_by", "reason")


def count_findings(report: Path) -> tuple[int | None, list[str]]:
    """Return the finding count and their identifiers, or None when unreadable."""
    try:
        if not report.is_file() or report.stat().st_size > MAX_REPORT_BYTES:
            return None, []
        body = json.loads(report.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None, []
    if isinstance(body, list) and all(
        isinstance(item, dict)
        and all(key in item for key in ("RuleID", "File", "StartLine", "Commit"))
        for item in body
    ):
        # Gitleaks: never copy Secret, Match or a source line, even from a redacted report.
        found = [
            f"{item['RuleID']}:{item['File']}:{item['StartLine']}:{item['Commit']}" for item in body
        ]
        return len(found), sorted(set(found))
    if isinstance(body, dict) and isinstance(body.get("dependencies"), list):
        # pip-audit: one entry per dependency, each with zero or more vulnerabilities.
        found = [
            f"{item.get('name')}=={item.get('version')}:{vulnerability.get('id')}"
            for item in body["dependencies"]
            if isinstance(item, dict)
            for vulnerability in (item.get("vulns") or [])
            if isinstance(vulnerability, dict)
        ]
        return len(found), sorted(set(found))
    if isinstance(body, dict) and "advisories" in body:
        # pnpm audit: keep package/advisory identifiers, never registry prose or paths.
        advisories = body["advisories"]
        metadata = body.get("metadata")
        counts = metadata.get("vulnerabilities") if isinstance(metadata, dict) else None
        severities = ("info", "low", "moderate", "high", "critical")
        if (
            not isinstance(advisories, dict)
            or not isinstance(counts, dict)
            or any(
                type(counts.get(severity)) is not int or counts[severity] < 0
                for severity in severities
            )
        ):
            return None, []
        found = []
        for advisory in advisories.values():
            if not isinstance(advisory, dict) or not isinstance(advisory.get("module_name"), str):
                return None, []
            identifier = advisory.get("github_advisory_id") or advisory.get("id")
            if not advisory["module_name"] or not identifier or type(identifier) not in (str, int):
                return None, []
            found.append(f"{advisory['module_name']}:{identifier}")
        if bool(found) != bool(sum(counts[severity] for severity in severities)):
            return None, []
        return len(found), sorted(set(found))
    if isinstance(body, dict) and isinstance(body.get("Results"), list):
        # Trivy: one result per scan target, each with zero or more vulnerabilities.
        found = [
            f"{vulnerability.get('VulnerabilityID')}:{vulnerability.get('PkgName')}"
            f"=={vulnerability.get('InstalledVersion')}"
            for result in body["Results"]
            if isinstance(result, dict)
            for vulnerability in (result.get("Vulnerabilities") or [])
            if isinstance(vulnerability, dict)
        ]
        return len(found), sorted(set(found))
    if isinstance(body, dict) and isinstance(body.get("results"), list):
        # bandit: the test identifier and location, never the flagged source line.
        found = [
            f"{item.get('test_id')}:{item.get('filename')}:{item.get('line_number')}"
            for item in body["results"]
            if isinstance(item, dict)
        ]
        return len(found), sorted(set(found))
    return None, []


def load_acknowledgements(path: Path) -> tuple[list[dict[str, Any]], str | None]:
    """Accepted advisories, or a refusal reason. A file we cannot trust suppresses nothing."""
    try:
        if not path.is_file():
            return [], None
        body = tomllib.loads(path.read_text(encoding="utf-8"))
        entries = body.get("acknowledgement") or []
        assert isinstance(entries, list)
    except (OSError, ValueError, AssertionError, tomllib.TOMLDecodeError):
        return [], "the acknowledgement file could not be read"
    accepted = []
    for entry in entries:
        if not isinstance(entry, dict) or any(
            not isinstance(entry.get(field), str) or not entry.get(field)
            for field in REQUIRED_FIELDS
        ):
            return [], "an acknowledgement is missing a required field"
        try:
            accepted_on = date.fromisoformat(entry["accepted_on"])
            review_by = date.fromisoformat(entry["review_by"])
        except ValueError:
            return [], f"{entry['id']} has an unreadable date"
        if review_by < accepted_on:
            return [], f"{entry['id']} is reviewed before it was accepted"
        if (review_by - accepted_on).days > MAX_ACKNOWLEDGEMENT_DAYS:
            return [], f"{entry['id']} is accepted for more than {MAX_ACKNOWLEDGEMENT_DAYS} days"
        accepted.append({**entry, "review_date": review_by})
    return accepted, None


def classify(
    actionable: list[dict[str, Any]], accepted: list[dict[str, Any]], today: date
) -> dict[str, Any]:
    """Split actionable findings by whether a current acceptance covers each one."""
    by_key = {(entry["id"], entry["package"]): entry for entry in accepted}
    unacknowledged, acknowledged, expired = [], [], []
    for finding in actionable:
        entry = by_key.get((finding["id"], finding["package"]))
        if entry is None:
            unacknowledged.append(finding)
        elif entry["review_date"] < today:
            # An expired acceptance is louder than none: it says someone decided and the
            # decision ran out.
            expired.append({**finding, "review_by": entry["review_by"]})
        else:
            acknowledged.append(
                {
                    **finding,
                    "review_by": entry["review_by"],
                    "days_left": (entry["review_date"] - today).days,
                }
            )
    seen = {(finding["id"], finding["package"]) for finding in actionable}
    return {
        "unacknowledged": unacknowledged,
        "acknowledged": acknowledged,
        "expired": expired,
        "unused_acknowledgements": sorted(
            f"{key[0]}:{key[1]}" for key in by_key if key not in seen
        ),
    }


def image_findings(report: Path) -> dict[str, Any]:
    """Break an image scan down far enough to triage it, without quoting any advisory text."""
    unreadable: dict[str, Any] = {
        "readable": False,
        "total": None,
        "by_severity": {},
        "by_target": {},
        "actionable": [],
        "policy": IMAGE_POLICY,
    }
    try:
        if not report.is_file() or report.stat().st_size > MAX_REPORT_BYTES:
            return unreadable
        body = json.loads(report.read_text(encoding="utf-8"))
        results = body["Results"]
        assert isinstance(results, list)
    except (OSError, ValueError, KeyError, AssertionError):
        return unreadable
    severity: Counter[str] = Counter()
    target: Counter[str] = Counter()
    actionable = []
    total = 0
    for result in results:
        if not isinstance(result, dict):
            continue
        for vulnerability in result.get("Vulnerabilities") or []:
            if not isinstance(vulnerability, dict):
                continue
            total += 1
            level = str(vulnerability.get("Severity") or "UNKNOWN")
            severity[level] += 1
            target[str(result.get("Type") or "unknown")] += 1
            fixed = vulnerability.get("FixedVersion")
            if level in ACTIONABLE_SEVERITY and fixed:
                actionable.append(
                    {
                        "id": vulnerability.get("VulnerabilityID"),
                        "package": vulnerability.get("PkgName"),
                        "installed": vulnerability.get("InstalledVersion"),
                        "fixed": fixed,
                        "severity": level,
                        "target": result.get("Type"),
                    }
                )
    operating_system = (body.get("Metadata") or {}).get("OS") or {}
    return {
        "readable": True,
        "os": f"{operating_system.get('Family')} {operating_system.get('Name')}".strip(),
        "total": total,
        "by_severity": dict(sorted(severity.items())),
        "by_target": dict(sorted(target.items())),
        "actionable": sorted(actionable, key=lambda item: (str(item["severity"]), str(item["id"]))),
        "policy": IMAGE_POLICY,
    }


def summarize(revision: str, run: str, scanners: list[str], root: Path) -> dict[str, Any]:
    entries = []
    for scanner in scanners:
        name, _, rest = scanner.partition(":")
        outcome, _, report = rest.partition(":")
        count, identifiers = count_findings(root / report) if report else (None, [])
        entries.append(
            {
                "scanner": name,
                "outcome": outcome or "unknown",
                "ran": outcome not in NOT_RUN,
                "reported_findings": outcome == "failure",
                "finding_count": count,
                "finding_ids": identifiers,
                "report": report or None,
            }
        )
    image = image_findings(root / IMAGE_REPORT)
    accepted, refusal = load_acknowledgements(root / ACKNOWLEDGEMENTS)
    verdict = classify(image["actionable"], accepted, datetime.now(UTC).date())
    image.update(verdict)
    image["acknowledgements_readable"] = refusal is None
    image["acknowledgement_refusal"] = refusal
    # A file we could not read suppresses nothing, so every actionable finding stands.
    failing = len(verdict["unacknowledged"]) + len(verdict["expired"])
    scan_failed = (
        not image["readable"]
        or refusal is not None
        or failing > 0
        or any(
            entry["outcome"] != "success"
            or entry["finding_count"] is None
            or (entry["report"] != IMAGE_REPORT and entry["finding_count"] > 0)
            for entry in entries
        )
    )
    return {
        "format": "execbound.security-scan-summary.v1",
        "generated_at": datetime.now(UTC).isoformat(),
        "revision": revision,
        "run": run,
        "gate": "scheduled and on demand; not a merge gate",
        "scanners": entries,
        "image": image,
        "actionable_image_findings": failing,
        "reported_findings": any(entry["reported_findings"] for entry in entries),
        "scan_failed": scan_failed,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--revision", default="")
    parser.add_argument("--run", default="")
    parser.add_argument(
        "--scanner",
        action="append",
        default=[],
        metavar="NAME:OUTCOME:REPORT",
        help="One scanner step, its step outcome and its report path (may be empty).",
    )
    args = parser.parse_args()
    summary = summarize(args.revision, args.run, args.scanner, Path.cwd())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    # The workflow decides whether to fail from this, so the policy stays in reviewable
    # Python rather than in a scanner's command line.
    step_output = os.environ.get("GITHUB_OUTPUT")
    if step_output:
        with open(step_output, "a", encoding="utf-8") as handle:
            handle.write(f"actionable_image_findings={summary['actionable_image_findings']}\n")
            handle.write(f"scan_failed={str(summary['scan_failed']).lower()}\n")
    headline = {key: value for key, value in summary.items() if key not in {"scanners", "image"}}
    print(json.dumps(headline))
    for entry in summary["scanners"]:
        print(f"  {entry['scanner']}: {entry['outcome']} findings={entry['finding_count']}")
    image = summary["image"]
    if image["readable"]:
        print(f"  image ({image['os']}): {image['total']} advisories {image['by_severity']}")
        if not image["acknowledgements_readable"]:
            print(f"    acknowledgements ignored: {image['acknowledgement_refusal']}")
        for label in ("unacknowledged", "expired"):
            for item in image[label]:
                print(
                    f"    {label} {item['severity']} {item['id']} {item['package']} "
                    f"{item['installed']} -> {item['fixed']} ({item['target']})"
                )
        for item in image["acknowledged"]:
            print(
                f"    accepted until {item['review_by']} ({item['days_left']} days left) "
                f"{item['id']} {item['package']}"
            )
        for unused in image["unused_acknowledgements"]:
            print(f"    unused acknowledgement, prune it: {unused}")


if __name__ == "__main__":
    main()
