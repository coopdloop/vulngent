from __future__ import annotations

from pathlib import Path

from sqlalchemy.orm import Session

from vulngent.db import repository as repo
from vulngent.ingestion.importer import import_file


def test_import_json_creates_vulns_assets_and_owners(session: Session) -> None:
    path = Path(__file__).parent.parent / "sample_data" / "sample_vulns.json"
    result = import_file(session, path)

    assert result.created == 4
    assert result.skipped_duplicate == []

    vulns = repo.list_vulnerabilities(session)
    assert len(vulns) == 4
    assert all(v.priority_score is not None for v in vulns)

    billing = next(v for v in vulns if v.external_id == "CVE-2026-30112")
    assert billing.asset.name == "billing-service"
    assert billing.asset.owner.name == "Priya Shah"
    assert billing.asset.owner.email == "priya@acme-corp.example"


def test_import_is_idempotent_on_rerun(session: Session) -> None:
    path = Path(__file__).parent.parent / "sample_data" / "sample_vulns.json"
    import_file(session, path)
    second = import_file(session, path)

    assert second.created == 0
    assert len(second.skipped_duplicate) == 4
