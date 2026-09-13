from __future__ import annotations

import datetime as dt
import json

import pytest
from sqlalchemy.orm import Session

from vulngent.db import repository as repo
from vulngent.db.models import CommitmentStatus, Severity, TimelineEvent, VulnStatus
from vulngent.ops_data import collect_ops_data, ops_payload


def _vuln(session: Session, ext_id: str, *, severity=Severity.HIGH, age_days=10, asset=None, due_days=None):
    now = dt.datetime.now(dt.timezone.utc)
    return repo.create_vulnerability(
        session,
        external_id=ext_id,
        title=f"vuln {ext_id}",
        severity=severity,
        asset=asset,
        discovered_at=now - dt.timedelta(days=age_days),
        due_date=(now - dt.timedelta(days=age_days) + dt.timedelta(days=due_days)) if due_days is not None else None,
    )


def _close(session: Session, vuln, *, days_ago=0) -> None:
    """Remediate a vuln and backdate the audit event, which is what ops_data reads."""
    repo.set_vulnerability_status(session, vuln, VulnStatus.REMEDIATED)
    session.flush()
    event = (
        session.query(TimelineEvent)
        .filter(TimelineEvent.vulnerability_id == vuln.id, TimelineEvent.event_type == "status_change")
        .order_by(TimelineEvent.id.desc())
        .first()
    )
    event.occurred_at = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days_ago)
    session.commit()


def test_mttr_measures_discovery_to_closure(session: Session) -> None:
    v = _vuln(session, "CVE-1", age_days=30)
    _close(session, v, days_ago=10)  # discovered 30d ago, closed 10d ago -> 20 days

    data = collect_ops_data(session)

    assert data.remediated_in_window == 1
    assert data.mttr_days == pytest.approx(20.0, abs=0.05)
    assert data.mttr_by_severity["high"] == pytest.approx(20.0, abs=0.05)


def test_sla_compliance_splits_met_and_missed(session: Session) -> None:
    early = _vuln(session, "CVE-EARLY", age_days=30, due_days=25)
    _close(session, early, days_ago=10)  # closed at day 20 of a 25-day SLA
    late = _vuln(session, "CVE-LATE", age_days=30, due_days=5)
    _close(session, late, days_ago=10)  # closed at day 20 of a 5-day SLA

    data = collect_ops_data(session)

    assert data.sla_met == 1
    assert data.sla_missed == 1
    assert data.sla_compliance == pytest.approx(0.5)


def test_closures_without_due_date_are_excluded_from_sla(session: Session) -> None:
    # create_vulnerability backfills a due date from the severity SLA table, so an
    # unmeasurable closure only happens when the due date is explicitly cleared.
    v = _vuln(session, "CVE-NODUE", age_days=10)
    v.due_date = None
    session.commit()
    _close(session, v, days_ago=1)

    data = collect_ops_data(session)

    assert data.remediated_in_window == 1
    assert data.sla_met == 0 and data.sla_missed == 0
    assert data.sla_compliance is None


def test_backlog_aging_buckets_open_vulns(session: Session) -> None:
    _vuln(session, "CVE-NEW", age_days=5)
    _vuln(session, "CVE-MID", age_days=45)
    _vuln(session, "CVE-OLD", age_days=200)

    data = collect_ops_data(session)

    assert data.aging["0-30d"] == 1
    assert data.aging["31-60d"] == 1
    assert data.aging["90d+"] == 1
    assert data.oldest_open_days >= 200


def test_net_backlog_change_is_intake_minus_closure(session: Session) -> None:
    _vuln(session, "CVE-A", age_days=3)
    _vuln(session, "CVE-B", age_days=3)
    closed = _vuln(session, "CVE-C", age_days=3)
    _close(session, closed, days_ago=1)

    data = collect_ops_data(session)

    assert data.discovered_in_window == 3
    assert data.remediated_in_window == 1
    assert data.net_backlog_change == 2


def test_window_excludes_older_closures(session: Session) -> None:
    old = _vuln(session, "CVE-OLD", age_days=200)
    _close(session, old, days_ago=120)
    recent = _vuln(session, "CVE-NEW", age_days=20)
    _close(session, recent, days_ago=5)

    windowed = collect_ops_data(session, window_days=90)
    all_time = collect_ops_data(session, window_days=None)

    assert windowed.remediated_in_window == 1
    assert all_time.remediated_in_window == 2


def test_owner_load_tracks_overdue_and_commitment_reliability(session: Session) -> None:
    owner = repo.get_or_create_stakeholder(session, "Ana Dev")
    asset = repo.get_or_create_asset(session, "svc-a", owner=owner)
    overdue = _vuln(session, "CVE-LATE", age_days=60, due_days=5, asset=asset)
    repo.set_priority(session, overdue)

    now = dt.datetime.now(dt.timezone.utc)
    met = repo.add_commitment(session, overdue, "fix it", now - dt.timedelta(days=1), stakeholder=owner)
    repo.update_commitment_status(session, met, CommitmentStatus.MET)
    missed = repo.add_commitment(session, overdue, "fix it again", now, stakeholder=owner)
    repo.update_commitment_status(session, missed, CommitmentStatus.MISSED)
    session.commit()

    data = collect_ops_data(session)

    ana = next(o for o in data.owners if o.owner_name == "Ana Dev")
    assert ana.open_count == 1
    assert ana.overdue_count == 1
    assert ana.commitments_met == 1 and ana.commitments_missed == 1
    assert ana.reliability == pytest.approx(0.5)


def test_owner_reliability_is_none_without_resolved_commitments(session: Session) -> None:
    owner = repo.get_or_create_stakeholder(session, "Bo Dev")
    asset = repo.get_or_create_asset(session, "svc-b", owner=owner)
    v = _vuln(session, "CVE-OPEN", age_days=5, asset=asset)
    repo.add_commitment(session, v, "later", dt.datetime.now(dt.timezone.utc), stakeholder=owner)
    session.commit()

    data = collect_ops_data(session)

    bo = next(o for o in data.owners if o.owner_name == "Bo Dev")
    assert bo.commitments_open == 1
    assert bo.reliability is None


def test_throughput_groups_by_week(session: Session) -> None:
    _vuln(session, "CVE-1", age_days=2)
    _vuln(session, "CVE-2", age_days=3)
    old = _vuln(session, "CVE-3", age_days=40)
    _close(session, old, days_ago=1)

    data = collect_ops_data(session)

    assert data.throughput, "expected at least one week bucket"
    assert sum(p.discovered for p in data.throughput) == 3
    assert sum(p.remediated for p in data.throughput) == 1
    assert all(p.week_start.weekday() == 0 for p in data.throughput)  # Mondays


def test_empty_ledger_produces_safe_nulls(session: Session) -> None:
    data = collect_ops_data(session)

    assert data.mttr_days is None
    assert data.sla_compliance is None
    assert data.oldest_open_days is None
    assert data.throughput == []


def test_ops_payload_is_json_serializable(session: Session) -> None:
    v = _vuln(session, "CVE-1", age_days=10, due_days=30)
    _close(session, v, days_ago=2)

    payload = ops_payload(collect_ops_data(session))
    json.dumps(payload)

    assert payload["counts"]["remediated"] == 1
    assert payload["sla"]["met"] == 1
    assert payload["slowest_closures"][0]["external_id"] == "CVE-1"
