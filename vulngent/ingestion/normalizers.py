"""Parsers to normalize scanner-native JSON into vulngent's VulnRecord format."""

from __future__ import annotations

import json
from pathlib import Path

from vulngent.ingestion.schema import VulnRecord


SEVERITY_MAP = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
}

def normalize_semgrep(report: dict, *, asset_name: str, repo_full_name: str) -> list[VulnRecord]:
    """Normalize a semgrep JSON report."""
    records = []
    for result in report.get("results", []):
        check_id = result["check_id"]
        extra = result["extra"]
        message = extra["message"]
        severity = extra["severity"]
        records.append(
            VulnRecord(
                external_id=check_id,
                title=message.split("\n")[0],
                description=message,
                severity=SEVERITY_MAP.get(severity, "info"),
                asset_name=asset_name,
                repo_full_name=repo_full_name,
            )
        )
    return records


def normalize_trufflehog(report_path: Path, *, asset_name: str, repo_full_name: str) -> list[VulnRecord]:
    """Normalize a trufflehog JSONL report."""
    records = []
    with open(report_path) as f:
        for line in f:
            finding = json.loads(line)
            records.append(
                VulnRecord(
                    external_id=f"trufflehog-{finding['SourceMetadata']['Data']['Git']['commit']}",
                    title="Hardcoded secret detected",
                    description=f"A hardcoded secret was found in {finding['SourceMetadata']['Data']['Git']['file']}",
                    severity="critical",
                    asset_name=asset_name,
                    repo_full_name=repo_full_name,
                )
            )
    return records


def normalize_trivy_fs(report: dict, *, asset_name: str, repo_full_name: str) -> list[VulnRecord]:
    """Normalize a trivy fs JSON report."""
    # This is a simplified version of the trivy_fs_to_vulngent.py script
    records = []
    for result in report.get("Results", []):
        for v in result.get("Vulnerabilities", []):
            records.append(
                VulnRecord(
                    external_id=v["VulnerabilityID"],
                    title=v.get("Title", ""),
                    description=v.get("Description", ""),
                    severity=v.get("Severity", "UNKNOWN").lower(),
                    cvss_score=v.get("CVSS", {}).get("nvd", {}).get("V3Score"),
                    asset_name=asset_name,
                    repo_full_name=repo_full_name,
                )
            )
    return records
