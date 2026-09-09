"""Map a `trivy image --format json` export to vulngent's normalized import
shape. Demo-only converter for vulnerables/web-dvwa:latest scan results.

Usage:
    python sample_data/demo/trivy_to_vulngent.py \
        sample_data/demo/trivy_dvwa.json sample_data/demo/dvwa_vulns.json
"""

from __future__ import annotations

import json
import sys

ASSET_NAME = "dvwa"
REPO_FULL_NAME = "digininja/DVWA"
SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNKNOWN": "info",
}
# Keep the demo ledger a manageable size; import everything with `--min-severity low`.
DEFAULT_MIN_SEVERITY = {"CRITICAL", "HIGH"}


def convert(trivy_report: dict, min_severities: set[str]) -> list[dict]:
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
                    "asset_name": ASSET_NAME,
                    "repo_full_name": REPO_FULL_NAME,
                    "asset_criticality": "high",
                    "owner_name": "Demo Security Owner",
                    "owner_email": "secops@example.com",
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
    in_path, out_path = sys.argv[1], sys.argv[2]
    min_sev = DEFAULT_MIN_SEVERITY
    if len(sys.argv) > 3:
        min_sev = {s.strip().upper() for s in sys.argv[3].split(",")}
    with open(in_path) as f:
        report = json.load(f)
    records = convert(report, min_sev)
    with open(out_path, "w") as f:
        json.dump(records, f, indent=2)
    print(f"Wrote {len(records)} records to {out_path}")
