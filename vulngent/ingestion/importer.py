"""Import vulnerabilities from a normalized JSON or CSV file into the ledger."""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy.orm import Session

from vulngent.db import repository as repo
from vulngent.ingestion.schema import VulnRecord


@dataclass
class ImportResult:
    created: int = 0
    skipped_duplicate: list[str] | None = None

    def __post_init__(self) -> None:
        if self.skipped_duplicate is None:
            self.skipped_duplicate = []


def _load_records(path: Path) -> list[dict]:
    if path.suffix.lower() == ".json":
        data = json.loads(path.read_text())
        return data if isinstance(data, list) else [data]
    if path.suffix.lower() == ".csv":
        with path.open(newline="") as f:
            return list(csv.DictReader(f))
    raise ValueError(f"Unsupported import file type: {path.suffix} (expected .json or .csv)")


def import_file(session: Session, path: str | Path) -> ImportResult:
    path = Path(path)
    raw_records = _load_records(path)
    result = ImportResult()

    for raw in raw_records:
        cleaned = {k: v for k, v in raw.items() if v not in ("", None)}
        record = VulnRecord.model_validate(cleaned)

        if repo.find_vulnerability_by_external_id(session, record.external_id):
            result.skipped_duplicate.append(record.external_id)
            continue

        owner = None
        if record.owner_name:
            owner = repo.get_or_create_stakeholder(
                session,
                record.owner_name,
                email=record.owner_email,
                slack_user_id=record.owner_slack_id,
                github_username=record.owner_github_username,
            )

        asset = repo.get_or_create_asset(
            session,
            record.asset_name,
            repo_full_name=record.repo_full_name,
            criticality=record.asset_criticality,
            owner=owner,
        )

        vuln = repo.create_vulnerability(
            session,
            external_id=record.external_id,
            title=record.title,
            description=record.description,
            severity=record.severity,
            cvss_score=record.cvss_score,
            asset=asset,
            discovered_at=record.discovered_at,
        )
        repo.set_priority(session, vuln, actor="importer")
        result.created += 1

    return result
