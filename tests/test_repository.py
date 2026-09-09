from __future__ import annotations

import datetime as dt

from sqlalchemy.orm import Session

from vulngent.db import repository as repo
from vulngent.db.models import Reachability, Severity, VulnStatus


def test_priority_score_prefers_severity_and_reachability(session: Session) -> None:
    asset = repo.get_or_create_asset(session, "svc-a", criticality="critical")
    v = repo.create_vulnerability(
        session, external_id="CVE-1", title="t", severity=Severity.CRITICAL, cvss_score=9.8, asset=asset
    )
    unreachable_score = repo.set_priority(session, v)

    repo.set_reachability(session, v, Reachability.REACHABLE)
    reachable_score = repo.set_priority(session, v)

    assert reachable_score > unreachable_score


def test_low_severity_low_criticality_scores_below_critical(session: Session) -> None:
    asset_low = repo.get_or_create_asset(session, "svc-low", criticality="low")
    low = repo.create_vulnerability(session, external_id="CVE-LOW", title="t", severity=Severity.LOW, asset=asset_low)
    repo.set_priority(session, low)

    asset_high = repo.get_or_create_asset(session, "svc-high", criticality="critical")
    critical = repo.create_vulnerability(
        session, external_id="CVE-CRIT", title="t", severity=Severity.CRITICAL, cvss_score=9.9, asset=asset_high
    )
    repo.set_priority(session, critical)

    assert critical.priority_score > low.priority_score


def test_get_or_create_stakeholder_is_idempotent(session: Session) -> None:
    a = repo.get_or_create_stakeholder(session, "Priya Shah", email="priya@example.com")
    b = repo.get_or_create_stakeholder(session, "Priya Shah", slack_user_id="U123")

    assert a.id == b.id
    assert b.email == "priya@example.com"
    assert b.slack_user_id == "U123"


def test_commitments_due_soon_filters_by_window(session: Session) -> None:
    asset = repo.get_or_create_asset(session, "svc-a")
    v = repo.create_vulnerability(session, external_id="CVE-1", title="t", asset=asset)

    soon = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=1)
    later = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=30)
    repo.add_commitment(session, v, "fix soon", soon)
    repo.add_commitment(session, v, "fix later", later)

    due = repo.list_commitments_due(session, within_days=3)
    assert [c.description for c in due] == ["fix soon"]


def test_timeline_records_key_transitions(session: Session) -> None:
    asset = repo.get_or_create_asset(session, "svc-a")
    v = repo.create_vulnerability(session, external_id="CVE-1", title="t", asset=asset)
    repo.set_reachability(session, v, Reachability.REACHABLE)

    event_types = [e.event_type for e in v.timeline_events]
    assert "ingested" in event_types
    assert "reachability_change" in event_types


def test_create_vulnerability_backfills_due_date_from_severity_sla(session: Session) -> None:
    asset = repo.get_or_create_asset(session, "svc-a")
    discovered = dt.datetime.now(dt.timezone.utc)

    critical = repo.create_vulnerability(
        session, external_id="CVE-CRIT", title="t", severity=Severity.CRITICAL, asset=asset, discovered_at=discovered
    )
    low = repo.create_vulnerability(
        session, external_id="CVE-LOW", title="t", severity=Severity.LOW, asset=asset, discovered_at=discovered
    )

    assert critical.due_date == discovered + dt.timedelta(days=repo.SLA_DAYS_BY_SEVERITY[Severity.CRITICAL])
    assert low.due_date == discovered + dt.timedelta(days=repo.SLA_DAYS_BY_SEVERITY[Severity.LOW])
    assert critical.due_date < low.due_date


def test_create_vulnerability_respects_explicit_due_date(session: Session) -> None:
    asset = repo.get_or_create_asset(session, "svc-a")
    explicit_due = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=3)

    v = repo.create_vulnerability(
        session, external_id="CVE-1", title="t", severity=Severity.CRITICAL, asset=asset, due_date=explicit_due
    )

    assert v.due_date == explicit_due


def test_days_overdue_and_is_overdue(session: Session) -> None:
    asset = repo.get_or_create_asset(session, "svc-a")
    now = dt.datetime.now(dt.timezone.utc)

    overdue = repo.create_vulnerability(
        session, external_id="CVE-OLD", title="t", severity=Severity.CRITICAL, asset=asset, discovered_at=now - dt.timedelta(days=30)
    )
    fresh = repo.create_vulnerability(
        session, external_id="CVE-NEW", title="t", severity=Severity.CRITICAL, asset=asset, discovered_at=now
    )

    assert repo.days_overdue(overdue) == 15  # 30 days old, 15-day critical SLA
    assert repo.is_overdue(overdue) is True
    assert repo.days_overdue(fresh) is None
    assert repo.is_overdue(fresh) is False


def test_days_overdue_ignores_remediated_vulns(session: Session) -> None:
    asset = repo.get_or_create_asset(session, "svc-a")
    now = dt.datetime.now(dt.timezone.utc)
    v = repo.create_vulnerability(
        session, external_id="CVE-1", title="t", severity=Severity.CRITICAL, asset=asset, discovered_at=now - dt.timedelta(days=30)
    )
    repo.set_vulnerability_status(session, v, VulnStatus.REMEDIATED)

    # days_overdue is purely date-math (still positive); is_overdue checks status too.
    assert repo.days_overdue(v) == 15
    assert repo.is_overdue(v) is False


def test_list_overdue_vulnerabilities_filters_and_orders_by_priority(session: Session) -> None:
    asset = repo.get_or_create_asset(session, "svc-a", criticality="critical")
    now = dt.datetime.now(dt.timezone.utc)

    low_overdue = repo.create_vulnerability(
        session, external_id="CVE-LOW", title="t", severity=Severity.LOW, cvss_score=2.0, asset=asset, discovered_at=now - dt.timedelta(days=100)
    )
    repo.set_priority(session, low_overdue)

    critical_overdue = repo.create_vulnerability(
        session, external_id="CVE-CRIT", title="t", severity=Severity.CRITICAL, cvss_score=9.9, asset=asset, discovered_at=now - dt.timedelta(days=30)
    )
    repo.set_priority(session, critical_overdue)

    not_overdue = repo.create_vulnerability(
        session, external_id="CVE-FRESH", title="t", severity=Severity.CRITICAL, asset=asset, discovered_at=now
    )
    repo.set_priority(session, not_overdue)

    remediated_overdue = repo.create_vulnerability(
        session, external_id="CVE-DONE", title="t", severity=Severity.CRITICAL, asset=asset, discovered_at=now - dt.timedelta(days=30)
    )
    repo.set_vulnerability_status(session, remediated_overdue, VulnStatus.REMEDIATED)

    overdue = repo.list_overdue_vulnerabilities(session)

    assert [v.external_id for v in overdue] == ["CVE-CRIT", "CVE-LOW"]
