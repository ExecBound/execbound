# SPDX-License-Identifier: AGPL-3.0-only
"""The scheduled security scan's retained finding population."""

import importlib.util
import json
from datetime import date
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location("scan_summary", "scripts/scan_summary.py")
assert spec is not None and spec.loader is not None
scan_summary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scan_summary)


def write(tmp_path: Path, name: str, body: object) -> str:
    (tmp_path / name).write_text(json.dumps(body), encoding="utf-8")
    return name


def test_pip_audit_vulnerabilities_are_counted_and_identified(tmp_path):
    report = write(
        tmp_path,
        "pip-audit.json",
        {
            "dependencies": [
                {"name": "quiet", "version": "1.0", "vulns": []},
                {
                    "name": "noisy",
                    "version": "2.1",
                    "vulns": [{"id": "GHSA-aaaa"}, {"id": "GHSA-bbbb"}],
                },
            ]
        },
    )
    count, identifiers = scan_summary.count_findings(tmp_path / report)
    assert count == 2
    assert identifiers == ["noisy==2.1:GHSA-aaaa", "noisy==2.1:GHSA-bbbb"]


def test_bandit_results_are_counted_without_the_flagged_source_line(tmp_path):
    report = write(
        tmp_path,
        "bandit.json",
        {
            "results": [
                {
                    "test_id": "B608",
                    "filename": "src/a.py",
                    "line_number": 12,
                    "code": "SECRET_LOOKING_SOURCE_LINE",
                }
            ]
        },
    )
    count, identifiers = scan_summary.count_findings(tmp_path / report)
    assert count == 1 and identifiers == ["B608:src/a.py:12"]
    # The population carries locations, never the code a scanner quoted back.
    assert "SECRET_LOOKING_SOURCE_LINE" not in json.dumps(identifiers)


def pnpm_report(advisories=None, **counts):
    return {
        "advisories": advisories or {},
        "metadata": {
            "vulnerabilities": {
                severity: counts.get(severity, 0)
                for severity in ("info", "low", "moderate", "high", "critical")
            }
        },
    }


def test_pnpm_audits_count_advisories_without_copying_registry_prose(tmp_path):
    report = write(
        tmp_path,
        "pnpm.json",
        pnpm_report(
            {
                "123": {
                    "module_name": "dependency",
                    "github_advisory_id": "GHSA-aaaa",
                    "overview": "PRIVATE_SOURCE",
                    "findings": [{"paths": ["PRIVATE_PATH"]}],
                }
            },
            high=1,
        ),
    )
    assert scan_summary.count_findings(tmp_path / report) == (1, ["dependency:GHSA-aaaa"])
    clean = write(tmp_path, "clean-pnpm.json", pnpm_report())
    assert scan_summary.count_findings(tmp_path / clean) == (0, [])


@pytest.mark.parametrize(
    "body",
    [
        {"error": {"code": "REGISTRY_UNAVAILABLE"}},
        {"advisories": {}},
        {"advisories": [], "metadata": {"vulnerabilities": {}}},
        pnpm_report(high=1),
        pnpm_report(high=-1),
        pnpm_report(high=True),
        pnpm_report({"123": {}}, high=1),
    ],
)
def test_pnpm_missing_or_inconsistent_evidence_is_not_a_clean_audit(tmp_path, body):
    report = write(tmp_path, "pnpm.json", body)
    assert scan_summary.count_findings(tmp_path / report) == (None, [])


@pytest.mark.parametrize(
    "outcome,body,failed",
    [
        ("success", pnpm_report(), False),
        ("success", {"error": "registry failed"}, True),
        ("failure", pnpm_report(), True),
        ("skipped", pnpm_report(), True),
        ("cancelled", pnpm_report(), True),
        ("success", pnpm_report({"123": {"module_name": "dependency", "id": 123}}, high=1), True),
    ],
)
def test_the_gate_requires_successful_readable_clean_non_image_scans(
    tmp_path, monkeypatch, outcome, body, failed
):
    monkeypatch.setattr(scan_summary, "IMAGE_REPORT", "trivy.json")
    write(tmp_path, "trivy.json", {"Results": []})
    write(tmp_path, "pnpm.json", body)
    summary = scan_summary.summarize(
        "abc",
        "1",
        [f"pnpm console:{outcome}:pnpm.json", "trivy image:success:trivy.json"],
        tmp_path,
    )
    assert summary["scan_failed"] is failed


def test_gitleaks_results_count_locations_without_matches_or_secrets(tmp_path):
    report = write(
        tmp_path,
        "gitleaks.json",
        [
            {
                "RuleID": "generic-api-key",
                "File": "example.py",
                "StartLine": 12,
                "Commit": "abc123",
                "Secret": "PRIVATE_VALUE",
                "Match": "PRIVATE_SOURCE",
            }
        ],
    )
    count, identifiers = scan_summary.count_findings(tmp_path / report)
    assert count == 1 and identifiers == ["generic-api-key:example.py:12:abc123"]
    assert "PRIVATE" not in json.dumps(identifiers)
    clean = write(tmp_path, "gitleaks-clean.json", [])
    assert scan_summary.count_findings(tmp_path / clean) == (0, [])


@pytest.mark.parametrize(
    "body", [{"unrecognized": []}, [{}], ["bad"], "text", {"dependencies": "not a list"}]
)
def test_an_unreadable_report_counts_nothing_rather_than_claiming_zero(tmp_path, body):
    report = write(tmp_path, "other.json", body)
    assert scan_summary.count_findings(tmp_path / report) == (None, [])


def test_a_missing_or_oversized_report_is_not_read(tmp_path, monkeypatch):
    assert scan_summary.count_findings(tmp_path / "absent.json") == (None, [])
    report = tmp_path / "huge.json"
    report.write_text(json.dumps({"results": []}), encoding="utf-8")
    monkeypatch.setattr(scan_summary, "MAX_REPORT_BYTES", 1)
    assert scan_summary.count_findings(report) == (None, [])


def test_the_summary_separates_a_clean_run_from_one_that_never_ran(tmp_path):
    clean = write(tmp_path, "clean.json", {"results": []})
    summary = scan_summary.summarize(
        "abc123",
        "42",
        [f"bandit:success:{clean}", "gitleaks:skipped:", "pip-audit:failure:absent.json"],
        tmp_path,
    )
    entries = {entry["scanner"]: entry for entry in summary["scanners"]}
    assert entries["bandit"]["ran"] and entries["bandit"]["finding_count"] == 0
    assert not entries["bandit"]["reported_findings"]
    # A skipped scanner is a coverage gap, never evidence that nothing was found.
    assert not entries["gitleaks"]["ran"]
    assert entries["gitleaks"]["finding_count"] is None
    assert entries["pip-audit"]["reported_findings"]
    assert summary["reported_findings"] is True
    assert summary["revision"] == "abc123" and summary["run"] == "42"
    assert "not a merge gate" in summary["gate"]


def trivy(results: list[dict], metadata: dict | None = None) -> dict:
    body: dict = {"Results": results}
    if metadata is not None:
        body["Metadata"] = metadata
    return body


def vulnerability(identifier: str, severity: str, fixed: str | None = None, **changes) -> dict:
    record = {
        "VulnerabilityID": identifier,
        "PkgName": changes.get("package", "libthing"),
        "InstalledVersion": changes.get("installed", "1.0"),
        "Severity": severity,
        "Title": "advisory prose that must not be retained",
    }
    if fixed is not None:
        record["FixedVersion"] = fixed
    return record


def test_an_image_scan_counts_every_advisory_and_breaks_it_down(tmp_path):
    report = tmp_path / "trivy.json"
    report.write_text(
        json.dumps(
            trivy(
                [
                    {
                        "Type": "debian",
                        "Vulnerabilities": [
                            vulnerability("CVE-1", "LOW"),
                            vulnerability("CVE-2", "HIGH", "2.0"),
                        ],
                    },
                    {"Type": "python-pkg", "Vulnerabilities": [vulnerability("CVE-3", "MEDIUM")]},
                    {"Type": "debian", "Vulnerabilities": None},
                ],
                {"OS": {"Family": "debian", "Name": "12.15"}},
            )
        ),
        encoding="utf-8",
    )
    summary = scan_summary.image_findings(report)
    assert summary["readable"] and summary["total"] == 3
    assert summary["os"] == "debian 12.15"
    assert summary["by_severity"] == {"HIGH": 1, "LOW": 1, "MEDIUM": 1}
    assert summary["by_target"] == {"debian": 2, "python-pkg": 1}


def test_only_a_high_or_critical_advisory_with_a_published_fix_is_actionable(tmp_path):
    report = tmp_path / "trivy.json"
    report.write_text(
        json.dumps(
            trivy(
                [
                    {
                        "Type": "debian",
                        "Vulnerabilities": [
                            # Severe but nothing to install yet.
                            vulnerability("CVE-unfixed", "CRITICAL"),
                            # Fixable but not severe enough to stop a run over.
                            vulnerability("CVE-low", "LOW", "9.9"),
                            vulnerability("CVE-act", "HIGH", "2.0", package="libpcre2-8-0"),
                            vulnerability("CVE-crit", "CRITICAL", "3.0", package="openssl"),
                        ],
                    }
                ]
            )
        ),
        encoding="utf-8",
    )
    summary = scan_summary.image_findings(report)
    assert summary["total"] == 4
    assert [item["id"] for item in summary["actionable"]] == ["CVE-crit", "CVE-act"]
    assert summary["actionable"][0]["fixed"] == "3.0"
    # The population records identifiers and versions, never the advisory's prose.
    assert "advisory prose" not in json.dumps(summary["actionable"])


def test_an_unreadable_image_report_is_not_a_clean_image(tmp_path):
    broken = tmp_path / "trivy.json"
    broken.write_text("{not json", encoding="utf-8")
    for path in (broken, tmp_path / "absent.json"):
        summary = scan_summary.image_findings(path)
        # Zero would read as "scanned and clean", which is the lie worth avoiding.
        assert summary["readable"] is False and summary["total"] is None
        assert summary["actionable"] == []


def test_the_trivy_report_also_counts_as_a_scanner_population(tmp_path):
    report = write(
        tmp_path,
        "trivy.json",
        trivy([{"Type": "debian", "Vulnerabilities": [vulnerability("CVE-9", "HIGH", "2.0")]}]),
    )
    count, identifiers = scan_summary.count_findings(tmp_path / report)
    assert count == 1 and identifiers == ["CVE-9:libthing==1.0"]


def test_the_summary_carries_the_actionable_count_for_the_workflow(tmp_path, monkeypatch):
    monkeypatch.setattr(scan_summary, "IMAGE_REPORT", "trivy.json")
    write(
        tmp_path,
        "trivy.json",
        trivy([{"Type": "debian", "Vulnerabilities": [vulnerability("CVE-9", "HIGH", "2.0")]}]),
    )
    summary = scan_summary.summarize("abc", "1", ["trivy image:success:trivy.json"], tmp_path)
    assert summary["actionable_image_findings"] == 1
    assert summary["image"]["policy"] == scan_summary.IMAGE_POLICY
    # An image advisory is not a scanner step failure; the step exits zero by design.
    assert summary["reported_findings"] is False


ENTRY = """
[[acknowledgement]]
id = "CVE-1"
package = "libthing"
accepted_on = "2026-01-01"
review_by = "2026-03-01"
reason = "upstream rebuild pending"
"""


def acknowledgements(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "acknowledged-advisories.toml"
    path.write_text(body, encoding="utf-8")
    return path


def finding(identifier: str = "CVE-1", package: str = "libthing") -> dict:
    return {
        "id": identifier,
        "package": package,
        "installed": "1.0",
        "fixed": "2.0",
        "severity": "HIGH",
        "target": "debian",
    }


def test_a_current_acknowledgement_covers_its_own_advisory_and_package(tmp_path):
    accepted, refusal = scan_summary.load_acknowledgements(acknowledgements(tmp_path, ENTRY))
    assert refusal is None and len(accepted) == 1
    verdict = scan_summary.classify([finding()], accepted, date(2026, 2, 1))
    assert verdict["acknowledged"][0]["days_left"] == 28
    assert verdict["unacknowledged"] == [] and verdict["expired"] == []


def test_the_same_advisory_in_another_package_is_a_separate_decision(tmp_path):
    accepted, _ = scan_summary.load_acknowledgements(acknowledgements(tmp_path, ENTRY))
    verdict = scan_summary.classify([finding(package="other-package")], accepted, date(2026, 2, 1))
    assert [item["package"] for item in verdict["unacknowledged"]] == ["other-package"]


def test_an_acknowledgement_stops_covering_the_day_after_its_review_date(tmp_path):
    accepted, _ = scan_summary.load_acknowledgements(acknowledgements(tmp_path, ENTRY))
    assert scan_summary.classify([finding()], accepted, date(2026, 3, 1))["acknowledged"]
    expired = scan_summary.classify([finding()], accepted, date(2026, 3, 2))["expired"]
    # Expired is reported as its own state: someone decided, and the decision ran out.
    assert [item["id"] for item in expired] == ["CVE-1"]


def test_an_acknowledgement_for_an_advisory_that_is_gone_is_reported_for_pruning(tmp_path):
    accepted, _ = scan_summary.load_acknowledgements(acknowledgements(tmp_path, ENTRY))
    verdict = scan_summary.classify([], accepted, date(2026, 2, 1))
    assert verdict["unused_acknowledgements"] == ["CVE-1:libthing"]


@pytest.mark.parametrize(
    ("body", "fragment"),
    [
        ("this is not toml [[[", "could not be read"),
        ('[[acknowledgement]]\nid = "CVE-1"\n', "missing a required field"),
        (ENTRY.replace('review_by = "2026-03-01"', 'review_by = "not-a-date"'), "unreadable date"),
        (ENTRY.replace('review_by = "2026-03-01"', 'review_by = "2025-01-01"'), "reviewed before"),
        (ENTRY.replace('review_by = "2026-03-01"', 'review_by = "2027-01-01"'), "more than 180"),
    ],
)
def test_a_file_that_cannot_be_trusted_suppresses_nothing(tmp_path, body, fragment):
    accepted, refusal = scan_summary.load_acknowledgements(acknowledgements(tmp_path, body))
    assert accepted == [] and refusal is not None and fragment in refusal
    # Every actionable finding stands when the record is unusable.
    verdict = scan_summary.classify([finding()], accepted, date(2026, 2, 1))
    assert len(verdict["unacknowledged"]) == 1


def test_an_absent_file_is_not_an_error_but_covers_nothing(tmp_path):
    accepted, refusal = scan_summary.load_acknowledgements(tmp_path / "absent.toml")
    assert accepted == [] and refusal is None
