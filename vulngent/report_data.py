"""Assemble a structured snapshot of the ledger for reporting. Kept separate from
`agents/tools.py::generate_status_report` (which returns prose for the LLM) so the
PDF/DOCX renderers work off real data rather than re-parsing markdown."""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from vulngent.config import get_settings
from vulngent.db import repository as repo
from vulngent.db.models import Commitment, Vulnerability, VulnStatus

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


@dataclass
class VulnSummary:
    id: int
    external_id: str
    title: str
    severity: str
    cvss_score: float | None
    status: str
    reachability: str
    priority_score: float | None
    asset_name: str
    owner_name: str
    due_date: dt.date | None
    days_overdue: int | None

    @property
    def is_overdue(self) -> bool:
        return self.days_overdue is not None


@dataclass
class CommitmentSummary:
    vulnerability_id: int
    vulnerability_external_id: str
    description: str
    due_date: dt.date
    status: str


@dataclass
class Branding:
    company_name: str
    title: str
    logo_path: str
    primary_color: str
    accent_color: str
    footer_text: str

    @classmethod
    def from_settings(cls) -> "Branding":
        s = get_settings()
        return cls(
            company_name=s.report_company_name or "vulngent",
            title=s.report_title or "Vulnerability Remediation Report",
            logo_path=s.report_logo_path,
            primary_color=s.report_primary_color or "#111827",
            accent_color=s.report_accent_color or "#2563EB",
            footer_text=s.report_footer_text or "Confidential",
        )


@dataclass
class ReportData:
    generated_at: dt.datetime
    open_count: int
    in_progress_count: int
    overdue_count: int
    by_severity: dict[str, int]
    top_vulns: list[VulnSummary]
    overdue_vulns: list[VulnSummary]
    commitments_due: list[CommitmentSummary]
    branding: Branding = field(default_factory=Branding.from_settings)

    @property
    def total_actionable(self) -> int:
        return self.open_count + self.in_progress_count


def _summarize(v: Vulnerability, *, as_of: dt.datetime) -> VulnSummary:
    return VulnSummary(
        id=v.id,
        external_id=v.external_id,
        title=v.title,
        severity=v.severity.value,
        cvss_score=v.cvss_score,
        status=v.status.value,
        reachability=v.reachability.value,
        priority_score=v.priority_score,
        asset_name=v.asset.name if v.asset else "-",
        owner_name=(v.asset.owner.name if v.asset and v.asset.owner else "-"),
        due_date=v.due_date.date() if v.due_date else None,
        days_overdue=repo.days_overdue(v, as_of=as_of),
    )


def collect_report_data(
    session: Session, *, top_n: int = 15, overdue_n: int = 10, commitments_within_days: int = 7
) -> ReportData:
    now = dt.datetime.now(dt.timezone.utc)
    open_vulns = repo.list_vulnerabilities(session, status=VulnStatus.OPEN)
    in_progress = repo.list_vulnerabilities(session, status=VulnStatus.IN_PROGRESS)
    overdue = repo.list_overdue_vulnerabilities(session)
    due_soon = repo.list_commitments_due(session, within_days=commitments_within_days)

    actionable = open_vulns + in_progress
    by_severity: dict[str, int] = {}
    for v in actionable:
        by_severity[v.severity.value] = by_severity.get(v.severity.value, 0) + 1
    by_severity = {sev: by_severity[sev] for sev in SEVERITY_ORDER if sev in by_severity}

    top = sorted(actionable, key=lambda v: v.priority_score or 0, reverse=True)[:top_n]

    def _commitment_summary(c: Commitment) -> CommitmentSummary:
        return CommitmentSummary(
            vulnerability_id=c.vulnerability_id,
            vulnerability_external_id=c.vulnerability.external_id if c.vulnerability else "-",
            description=c.description,
            due_date=c.committed_date.date(),
            status=c.status.value,
        )

    return ReportData(
        generated_at=now,
        open_count=len(open_vulns),
        in_progress_count=len(in_progress),
        overdue_count=len(overdue),
        by_severity=by_severity,
        top_vulns=[_summarize(v, as_of=now) for v in top],
        overdue_vulns=[_summarize(v, as_of=now) for v in overdue[:overdue_n]],
        commitments_due=[_commitment_summary(c) for c in due_soon],
    )
