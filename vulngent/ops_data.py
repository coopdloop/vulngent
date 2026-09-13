"""Remediation operations analytics: are we actually closing things, on time, and who owes what.

The posture dashboard answers "what's broken right now" and the usage dashboard answers
"what did the agents cost"; this answers "is the remediation program working" — MTTR,
SLA compliance, intake vs. closure throughput, backlog aging, and per-owner accountability.

Derived from TimelineEvent (the audit trail already written on every status change) so no
new bookkeeping is required.
"""

from __future__ import annotations

import datetime as dt
from collections import defaultdict
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from vulngent.db import repository as repo
from vulngent.db.models import (
    Commitment,
    CommitmentStatus,
    TimelineEvent,
    Vulnerability,
    VulnStatus,
)
from vulngent.report_data import SEVERITY_ORDER, Branding

#: Open-age buckets (days). Upper bound None = "and older".
AGING_BUCKETS: tuple[tuple[str, int, int | None], ...] = (
    ("0-30d", 0, 30),
    ("31-60d", 31, 60),
    ("61-90d", 61, 90),
    ("90d+", 91, None),
)


def _aware(value: dt.datetime | None) -> dt.datetime | None:
    """SQLite returns naive datetimes even for timezone=True columns."""
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=dt.timezone.utc)


@dataclass
class ClosureStat:
    """One remediated vulnerability's close performance."""

    vulnerability_id: int
    external_id: str
    severity: str
    days_to_remediate: float
    closed_at: dt.datetime
    within_sla: bool | None  # None when the vuln had no due date


@dataclass
class OwnerLoad:
    owner_name: str
    open_count: int
    overdue_count: int
    commitments_open: int
    commitments_met: int
    commitments_missed: int

    @property
    def reliability(self) -> float | None:
        """Share of resolved commitments that were met. None when nothing has resolved yet."""
        resolved = self.commitments_met + self.commitments_missed
        return (self.commitments_met / resolved) if resolved else None


@dataclass
class ThroughputPoint:
    week_start: dt.date
    discovered: int
    remediated: int

    @property
    def net(self) -> int:
        """Positive = backlog grew that week."""
        return self.discovered - self.remediated


@dataclass
class OpsReportData:
    generated_at: dt.datetime
    window_days: int | None
    since: dt.datetime | None
    backlog_open: int
    backlog_in_progress: int
    remediated_in_window: int
    discovered_in_window: int
    mttr_days: float | None
    mttr_by_severity: dict[str, float]
    sla_met: int
    sla_missed: int
    aging: dict[str, int]
    oldest_open_days: int | None
    throughput: list[ThroughputPoint]
    owners: list[OwnerLoad]
    slowest_closures: list[ClosureStat]
    branding: Branding = field(default_factory=Branding.from_settings)

    @property
    def window_label(self) -> str:
        return f"last {self.window_days} days" if self.window_days else "all time"

    @property
    def sla_compliance(self) -> float | None:
        """Share of closures with a due date that beat it. None when none are measurable."""
        total = self.sla_met + self.sla_missed
        return (self.sla_met / total) if total else None

    @property
    def net_backlog_change(self) -> int:
        return self.discovered_in_window - self.remediated_in_window


def _week_start(day: dt.date) -> dt.date:
    return day - dt.timedelta(days=day.weekday())


def _bucket_for(age_days: int) -> str:
    for label, low, high in AGING_BUCKETS:
        if age_days >= low and (high is None or age_days <= high):
            return label
    return AGING_BUCKETS[-1][0]


def collect_ops_data(session: Session, *, window_days: int | None = 90, slowest_n: int = 8) -> OpsReportData:
    """Aggregate remediation throughput/SLA performance. `window_days=None` means all time."""
    now = dt.datetime.now(dt.timezone.utc)
    window = window_days or None
    since = now - dt.timedelta(days=window) if window else None

    vulns = list(session.execute(select(Vulnerability)).scalars().all())
    by_id = {v.id: v for v in vulns}

    open_vulns = [v for v in vulns if v.status == VulnStatus.OPEN]
    in_progress = [v for v in vulns if v.status == VulnStatus.IN_PROGRESS]
    actionable = open_vulns + in_progress

    # --- closures, from the audit trail -------------------------------------
    closure_stmt = select(TimelineEvent).where(
        TimelineEvent.event_type == "status_change",
        TimelineEvent.description.like("%-> remediated%"),
    )
    closures: list[ClosureStat] = []
    for event in session.execute(closure_stmt).scalars().all():
        vuln = by_id.get(event.vulnerability_id)
        closed_at = _aware(event.occurred_at) or now
        if vuln is None or (since is not None and closed_at < since):
            continue
        discovered = _aware(vuln.discovered_at) or closed_at
        due = _aware(vuln.due_date)
        closures.append(
            ClosureStat(
                vulnerability_id=vuln.id,
                external_id=vuln.external_id,
                severity=vuln.severity.value,
                days_to_remediate=max((closed_at - discovered).total_seconds() / 86400.0, 0.0),
                closed_at=closed_at,
                within_sla=(closed_at <= due) if due else None,
            )
        )

    mttr = (sum(c.days_to_remediate for c in closures) / len(closures)) if closures else None
    sev_times: dict[str, list[float]] = defaultdict(list)
    for c in closures:
        sev_times[c.severity].append(c.days_to_remediate)
    mttr_by_severity = {
        sev: sum(sev_times[sev]) / len(sev_times[sev]) for sev in SEVERITY_ORDER if sev in sev_times
    }
    sla_met = sum(1 for c in closures if c.within_sla is True)
    sla_missed = sum(1 for c in closures if c.within_sla is False)

    discovered_in_window = [
        v for v in vulns if since is None or (_aware(v.discovered_at) or now) >= since
    ]

    # --- weekly intake vs closure -------------------------------------------
    weeks: dict[dt.date, list[int]] = defaultdict(lambda: [0, 0])
    for v in discovered_in_window:
        weeks[_week_start((_aware(v.discovered_at) or now).date())][0] += 1
    for c in closures:
        weeks[_week_start(c.closed_at.date())][1] += 1
    throughput = [
        ThroughputPoint(week_start=w, discovered=counts[0], remediated=counts[1])
        for w, counts in sorted(weeks.items())
    ]

    # --- backlog aging -------------------------------------------------------
    aging = {label: 0 for label, _, _ in AGING_BUCKETS}
    oldest_open_days: int | None = None
    for v in actionable:
        age = max((now - (_aware(v.discovered_at) or now)).days, 0)
        aging[_bucket_for(age)] += 1
        oldest_open_days = age if oldest_open_days is None else max(oldest_open_days, age)

    # --- per-owner load and commitment reliability ---------------------------
    owner_acc: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0, 0, 0])
    for v in actionable:
        name = v.asset.owner.name if v.asset and v.asset.owner else "Unassigned"
        owner_acc[name][0] += 1
        if repo.days_overdue(v, as_of=now) is not None:
            owner_acc[name][1] += 1
    for c in session.execute(select(Commitment)).scalars().all():
        vuln = by_id.get(c.vulnerability_id)
        name = (
            c.stakeholder.name
            if c.stakeholder
            else (vuln.asset.owner.name if vuln and vuln.asset and vuln.asset.owner else "Unassigned")
        )
        if c.status == CommitmentStatus.OPEN:
            owner_acc[name][2] += 1
        elif c.status == CommitmentStatus.MET:
            owner_acc[name][3] += 1
        elif c.status == CommitmentStatus.MISSED:
            owner_acc[name][4] += 1
    owners = sorted(
        (
            OwnerLoad(
                owner_name=name,
                open_count=v[0],
                overdue_count=v[1],
                commitments_open=v[2],
                commitments_met=v[3],
                commitments_missed=v[4],
            )
            for name, v in owner_acc.items()
        ),
        key=lambda o: (o.overdue_count, o.open_count),
        reverse=True,
    )

    return OpsReportData(
        generated_at=now,
        window_days=window,
        since=since,
        backlog_open=len(open_vulns),
        backlog_in_progress=len(in_progress),
        remediated_in_window=len(closures),
        discovered_in_window=len(discovered_in_window),
        mttr_days=mttr,
        mttr_by_severity=mttr_by_severity,
        sla_met=sla_met,
        sla_missed=sla_missed,
        aging=aging,
        oldest_open_days=oldest_open_days,
        throughput=throughput,
        owners=owners,
        slowest_closures=sorted(closures, key=lambda c: c.days_to_remediate, reverse=True)[:slowest_n],
    )


def ops_payload(data: OpsReportData) -> dict:
    """JSON-serializable shape for /api/ops."""
    return {
        "generated_at": data.generated_at.isoformat(),
        "window_days": data.window_days,
        "window_label": data.window_label,
        "counts": {
            "backlog_open": data.backlog_open,
            "backlog_in_progress": data.backlog_in_progress,
            "remediated": data.remediated_in_window,
            "discovered": data.discovered_in_window,
            "net_backlog_change": data.net_backlog_change,
            "oldest_open_days": data.oldest_open_days,
        },
        "mttr_days": round(data.mttr_days, 1) if data.mttr_days is not None else None,
        "mttr_by_severity": {k: round(v, 1) for k, v in data.mttr_by_severity.items()},
        "sla": {
            "met": data.sla_met,
            "missed": data.sla_missed,
            "compliance": round(data.sla_compliance, 4) if data.sla_compliance is not None else None,
        },
        "aging": data.aging,
        "throughput": [
            {
                "week_start": p.week_start.isoformat(),
                "discovered": p.discovered,
                "remediated": p.remediated,
                "net": p.net,
            }
            for p in data.throughput
        ],
        "owners": [
            {
                "owner": o.owner_name,
                "open_count": o.open_count,
                "overdue_count": o.overdue_count,
                "commitments_open": o.commitments_open,
                "commitments_met": o.commitments_met,
                "commitments_missed": o.commitments_missed,
                "reliability": round(o.reliability, 4) if o.reliability is not None else None,
            }
            for o in data.owners
        ],
        "slowest_closures": [
            {
                "vulnerability_id": c.vulnerability_id,
                "external_id": c.external_id,
                "severity": c.severity,
                "days_to_remediate": round(c.days_to_remediate, 1),
                "closed_at": c.closed_at.isoformat(),
                "within_sla": c.within_sla,
            }
            for c in data.slowest_closures
        ],
    }
