from __future__ import annotations

import datetime as dt

from sqlalchemy.orm import Session

from vulngent.db import repository as repo
from vulngent.db.models import Reachability, Severity


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
