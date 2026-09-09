"""Map a `trivy fs --scanners vuln` export (SCA/dependency scan of a source repo,
as opposed to a container image) to vulngent's normalized import shape.

Usage:
    python sample_data/demo/trivy_fs_to_vulngent.py \
        trivy_fs.json out.json --asset my-app --repo owner/my-app [MIN_SEVERITIES]

    MIN_SEVERITIES defaults to CRITICAL,HIGH.
"""

from __future__ import annotations

import argparse
import json

SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNKNOWN": "info",
}


def convert(trivy_report: dict, *, asset_name: str, repo_full_name: str, min_severities: set[str]) -> list[dict]:
    records = []
    for result in trivy_report.get("Results", []):
        for v in result.get("Vulnerabilities") or []:
            severity = v.get("Severity", "UNKNOWN")
            if severity not in min_severities:
                continue
            pkg = v.get("PkgName", "unknown-package")
            installed = v.get("InstalledVersion", "?")
            fixed = v.get("FixedVersion")
            desc = v.get("Description") or v.get("Title") or ""
            fix_note = f" Fixed in {fixed}." if fixed else " No fix available yet."
            records.append(
                {
                    "external_id": v["VulnerabilityID"],
                    "title": v.get("Title") or f"{pkg} {installed}: {v['VulnerabilityID']}",
                    "description": f"{desc}\n\nPackage: {pkg} {installed}.{fix_note}".strip(),
                    "severity": SEVERITY_MAP.get(severity, "info"),
                    "cvss_score": _best_cvss(v),
                    "asset_name": asset_name,
                    "repo_full_name": repo_full_name,
                    "asset_criticality": "medium",
                }
            )
    return records


def _best_cvss(v: dict) -> float | None:
    cvss = v.get("CVSS") or {}
    for source in ("nvd", "redhat", "ghsa"):
        entry = cvss.get(source)
        if entry and entry.get("V3Score") is not None:
            return entry["V3Score"]
    for entry in cvss.values():
        if entry.get("V3Score") is not None:
            return entry["V3Score"]
    return None


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("in_path")
    parser.add_argument("out_path")
    parser.add_argument("--asset", required=True, help="Logical asset name")
    parser.add_argument("--repo", required=True, help="GitHub 'owner/repo'")
    parser.add_argument("--min-severity", default="CRITICAL,HIGH", help="Comma-separated Trivy severities to keep")
    args = parser.parse_args()

    min_sev = {s.strip().upper() for s in args.min_severity.split(",")}
    with open(args.in_path) as f:
        report = json.load(f)
    records = convert(report, asset_name=args.asset, repo_full_name=args.repo, min_severities=min_sev)
    with open(args.out_path, "w") as f:
        json.dump(records, f, indent=2)
    print(f"Wrote {len(records)} records to {args.out_path}")
