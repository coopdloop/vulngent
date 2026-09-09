from __future__ import annotations

import json
from pathlib import Path

from vulngent.ingestion import normalizers


def test_normalize_semgrep() -> None:
    report = {
        "results": [
            {
                "check_id": "test-rule",
                "extra": {
                    "message": "Test finding",
                    "severity": "ERROR",
                },
            }
        ]
    }
    records = normalizers.normalize_semgrep(report, asset_name="test", repo_full_name="owner/repo")
    assert len(records) == 1
    assert records[0].external_id == "test-rule"
    assert records[0].severity == "high"


def test_normalize_trufflehog() -> None:
    report_path = Path("/tmp/test_trufflehog.jsonl")
    with open(report_path, "w") as f:
        f.write(
            '{"SourceMetadata": {"Data": {"Git": {"commit": "123", "file": "foo.txt"}}}}'
        )
    records = normalizers.normalize_trufflehog(report_path, asset_name="test", repo_full_name="owner/repo")
    assert len(records) == 1
    assert records[0].external_id == "trufflehog-123"
    assert records[0].severity == "critical"


def test_normalize_trivy_fs() -> None:
    report = {
        "Results": [
            {
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-TEST-1",
                        "Title": "Test CVE",
                        "Description": "Desc",
                        "Severity": "HIGH",
                        "CVSS": {"nvd": {"V3Score": 9.8}},
                    }
                ]
            }
        ]
    }
    records = normalizers.normalize_trivy_fs(report, asset_name="test", repo_full_name="owner/repo")
    assert len(records) == 1
    assert records[0].external_id == "CVE-TEST-1"
    assert records[0].cvss_score == 9.8
