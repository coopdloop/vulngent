from __future__ import annotations

import datetime as dt

from sqlalchemy.orm import Session

from vulngent.db import repository as repo
from vulngent.db.models import Severity, VulnStatus
from vulngent.report_data import collect_report_data


def test_collect_report_data_counts_and_severity_breakdown(session: Session) -> None:
    asset = repo.get_or_create_asset(session, "svc-a", criticality="critical")
    now = dt.datetime.now(dt.timezone.utc)

    v1 = repo.create_vulnerability(session, external_id="CVE-1", title="a", severity=Severity.CRITICAL, cvss_score=9.8, asset=asset, discovered_at=now)
    repo.set_priority(session, v1)
    v2 = repo.create_vulnerability(session, external_id="CVE-2", title="b", severity=Severity.HIGH, cvss_score=8.0, asset=asset, discovered_at=now)
    repo.set_priority(session, v2)
    v3 = repo.create_vulnerability(session, external_id="CVE-3", title="c", severity=Severity.LOW, asset=asset, discovered_at=now)
    repo.set_priority(session, v3)
    repo.set_vulnerability_status(session, v3, VulnStatus.REMEDIATED)  # excluded from counts

    data = collect_report_data(session)

    assert data.open_count == 2
    assert data.in_progress_count == 0
    assert data.by_severity == {"critical": 1, "high": 1}


def test_collect_report_data_orders_top_vulns_by_priority(session: Session) -> None:
    asset = repo.get_or_create_asset(session, "svc-a", criticality="critical")
    now = dt.datetime.now(dt.timezone.utc)

    low = repo.create_vulnerability(session, external_id="CVE-LOW", title="low", severity=Severity.LOW, asset=asset, discovered_at=now)
    repo.set_priority(session, low)
    high = repo.create_vulnerability(session, external_id="CVE-HIGH", title="high", severity=Severity.CRITICAL, cvss_score=9.9, asset=asset, discovered_at=now)
    repo.set_priority(session, high)

    data = collect_report_data(session, top_n=5)

    assert [v.external_id for v in data.top_vulns] == ["CVE-HIGH", "CVE-LOW"]


def test_collect_report_data_flags_overdue_vulns(session: Session) -> None:
    asset = repo.get_or_create_asset(session, "svc-a", criticality="critical")
    now = dt.datetime.now(dt.timezone.utc)

    overdue = repo.create_vulnerability(
        session, external_id="CVE-OLD", title="old", severity=Severity.CRITICAL, cvss_score=9.8, asset=asset,
        discovered_at=now - dt.timedelta(days=30),
    )
    repo.set_priority(session, overdue)
    fresh = repo.create_vulnerability(
        session, external_id="CVE-NEW", title="new", severity=Severity.CRITICAL, cvss_score=9.8, asset=asset,
        discovered_at=now,
    )
    repo.set_priority(session, fresh)

    data = collect_report_data(session)

    assert data.overdue_count == 1
    assert [v.external_id for v in data.overdue_vulns] == ["CVE-OLD"]

    top_by_id = {v.external_id: v for v in data.top_vulns}
    assert top_by_id["CVE-OLD"].is_overdue is True
    assert top_by_id["CVE-OLD"].days_overdue == 15
    assert top_by_id["CVE-NEW"].is_overdue is False
    assert top_by_id["CVE-NEW"].days_overdue is None


def test_collect_report_data_overdue_respects_overdue_n_limit(session: Session) -> None:
    asset = repo.get_or_create_asset(session, "svc-a", criticality="critical")
    now = dt.datetime.now(dt.timezone.utc)

    for i in range(5):
        v = repo.create_vulnerability(
            session, external_id=f"CVE-{i}", title=f"t{i}", severity=Severity.CRITICAL, cvss_score=9.0, asset=asset,
            discovered_at=now - dt.timedelta(days=30),
        )
        repo.set_priority(session, v)

    data = collect_report_data(session, overdue_n=2)

    assert data.overdue_count == 5  # true count, unbounded
    assert len(data.overdue_vulns) == 2  # rendered list, bounded


def test_collect_report_data_commitments_due_within_window(session: Session) -> None:
    asset = repo.get_or_create_asset(session, "svc-a")
    v = repo.create_vulnerability(session, external_id="CVE-1", title="t", asset=asset)

    soon = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=2)
    later = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=30)
    repo.add_commitment(session, v, "fix soon", soon)
    repo.add_commitment(session, v, "fix later", later)

    data = collect_report_data(session, commitments_within_days=7)

    assert [c.description for c in data.commitments_due] == ["fix soon"]
