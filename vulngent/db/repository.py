"""CRUD + query helpers over the ledger. Kept as plain functions (not a class) so they
can be wrapped directly as agent tools, and reused by the CLI and importer.
"""

from __future__ import annotations

import datetime as dt

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from vulngent.db.models import (
    Asset,
    Commitment,
    CommitmentStatus,
    CommChannel,
    CommDirection,
    CommunicationLog,
    ExternalReference,
    Reachability,
    RefType,
    RemediationStep,
    Severity,
    Stakeholder,
    StepStatus,
    TimelineEvent,
    Vulnerability,
    VulnStatus,
)

# --- Stakeholders & assets -------------------------------------------------


def get_or_create_stakeholder(
    session: Session,
    name: str,
    *,
    role: str = "service_owner",
    email: str | None = None,
    slack_user_id: str | None = None,
    github_username: str | None = None,
) -> Stakeholder:
    existing = session.execute(select(Stakeholder).where(Stakeholder.name == name)).scalar_one_or_none()
    if existing:
        for field, value in (
            ("email", email),
            ("slack_user_id", slack_user_id),
            ("github_username", github_username),
        ):
            if value:
                setattr(existing, field, value)
        return existing
    stakeholder = Stakeholder(
        name=name, role=role, email=email, slack_user_id=slack_user_id, github_username=github_username
    )
    session.add(stakeholder)
    session.flush()
    return stakeholder


def get_or_create_asset(
    session: Session,
    name: str,
    *,
    repo_full_name: str | None = None,
    environment: str = "production",
    criticality: str = "medium",
    owner: Stakeholder | None = None,
) -> Asset:
    existing = session.execute(select(Asset).where(Asset.name == name)).scalar_one_or_none()
    if existing:
        return existing
    asset = Asset(
        name=name,
        repo_full_name=repo_full_name,
        environment=environment,
        criticality=criticality,
        owner=owner,
    )
    session.add(asset)
    session.flush()
    return asset


def find_asset_by_name(session: Session, name: str) -> Asset | None:
    return session.execute(select(Asset).where(Asset.name == name)).scalar_one_or_none()


def set_asset_repo(session: Session, asset: Asset, repo_full_name: str) -> None:
    asset.repo_full_name = repo_full_name


def list_assets(session: Session) -> list[Asset]:
    """Return every asset alphabetically with its owner overviews."""
    stmt = select(Asset).order_by(Asset.name)
    return list(session.execute(stmt).scalars().all())


def search_vulnerabilities(
    session: Session,
    *,
    status: VulnStatus | None = None,
    severity: Severity | None = None,
    asset_name: str | None = None,
    is_overdue: bool | None = None,
    limit: int | None = None,
) -> list[Vulnerability]:
    stmt = select(Vulnerability)
    if status is not None:
        stmt = stmt.where(Vulnerability.status == status)
    if severity is not None:
        stmt = stmt.where(Vulnerability.severity == severity)
    if asset_name:
        asset = find_asset_by_name(session, asset_name)
        if not asset:
            return []
        stmt = stmt.where(Vulnerability.asset_id == asset.id)
    now = dt.datetime.now(dt.timezone.utc)
    if is_overdue is True:
        stmt = stmt.where(
            Vulnerability.status.in_((VulnStatus.OPEN, VulnStatus.IN_PROGRESS)),
            Vulnerability.due_date.is_not(None),
            Vulnerability.due_date < now,
        )
    elif is_overdue is False:
        stmt = stmt.where(
            or_(Vulnerability.due_date.is_(None), Vulnerability.due_date >= now)
        )
    stmt = stmt.order_by(Vulnerability.priority_score.desc().nulls_last())
    if limit:
        stmt = stmt.limit(limit)
    return list(session.execute(stmt).scalars().all())


# --- Vulnerabilities ---------------------------------------------------

# Default remediation SLA windows by severity, used to backfill due_date on ingest
# when a scanner/import doesn't supply one. Industry-typical (e.g. critical fixed
# within a sprint, low severity within a quarter) - override per-org via due_date.
SLA_DAYS_BY_SEVERITY = {
    Severity.CRITICAL: 15,
    Severity.HIGH: 30,
    Severity.MEDIUM: 60,
    Severity.LOW: 90,
    Severity.INFO: 180,
}


def create_vulnerability(
    session: Session,
    *,
    external_id: str,
    title: str,
    description: str = "",
    severity: Severity = Severity.MEDIUM,
    cvss_score: float | None = None,
    asset: Asset | None = None,
    discovered_at: dt.datetime | None = None,
    due_date: dt.datetime | None = None,
) -> Vulnerability:
    discovered = discovered_at or dt.datetime.now(dt.timezone.utc)
    vuln = Vulnerability(
        external_id=external_id,
        title=title,
        description=description,
        severity=severity,
        cvss_score=cvss_score,
        asset=asset,
        discovered_at=discovered,
        due_date=due_date or (discovered + dt.timedelta(days=SLA_DAYS_BY_SEVERITY.get(severity, 90))),
    )
    session.add(vuln)
    session.flush()
    add_timeline_event(session, vuln, event_type="ingested", description=f"Vulnerability {external_id} ingested.")
    return vuln


def get_vulnerability(session: Session, vuln_id: int) -> Vulnerability | None:
    return session.get(Vulnerability, vuln_id)


def find_vulnerability_by_external_id(session: Session, external_id: str) -> Vulnerability | None:
    return session.execute(
        select(Vulnerability).where(Vulnerability.external_id == external_id)
    ).scalar_one_or_none()


def list_vulnerabilities(
    session: Session,
    *,
    status: VulnStatus | None = None,
    severity: Severity | None = None,
) -> list[Vulnerability]:
    stmt = select(Vulnerability)
    if status is not None:
        stmt = stmt.where(Vulnerability.status == status)
    if severity is not None:
        stmt = stmt.where(Vulnerability.severity == severity)
    stmt = stmt.order_by(Vulnerability.priority_score.desc().nulls_last())
    return list(session.execute(stmt).scalars().all())


def set_vulnerability_status(session: Session, vuln: Vulnerability, status: VulnStatus, *, actor: str = "agent") -> None:
    old = vuln.status
    vuln.status = status
    add_timeline_event(
        session, vuln, event_type="status_change", description=f"Status changed: {old.value} -> {status.value}", actor=actor
    )


def set_reachability(
    session: Session, vuln: Vulnerability, reachability: Reachability, *, notes: str = "", actor: str = "agent"
) -> None:
    vuln.reachability = reachability
    desc = f"Reachability set to {reachability.value}."
    if notes:
        desc += f" Notes: {notes}"
    add_timeline_event(session, vuln, event_type="reachability_change", description=desc, actor=actor)


SEVERITY_WEIGHT = {
    Severity.CRITICAL: 40.0,
    Severity.HIGH: 30.0,
    Severity.MEDIUM: 15.0,
    Severity.LOW: 5.0,
    Severity.INFO: 1.0,
}

CRITICALITY_WEIGHT = {"critical": 20.0, "high": 15.0, "medium": 8.0, "low": 3.0}

REACHABILITY_WEIGHT = {
    Reachability.REACHABLE: 20.0,
    Reachability.UNKNOWN: 8.0,
    Reachability.PENDING_ANALYST: 8.0,
    Reachability.NOT_REACHABLE: -15.0,
}


def compute_priority_score(vuln: Vulnerability) -> tuple[float, str]:
    """A transparent, additive risk score. Higher = fix sooner.

    Not a substitute for a real risk model - meant to surface obvious low-hanging
    fruit (high severity + reachable + easy) and let an analyst override via notes.
    """
    severity_pts = SEVERITY_WEIGHT.get(vuln.severity, 10.0)
    cvss_pts = (vuln.cvss_score or 0.0) * 2.0
    criticality = vuln.asset.criticality if vuln.asset else "medium"
    criticality_pts = CRITICALITY_WEIGHT.get(criticality, 8.0)
    reachability_pts = REACHABILITY_WEIGHT.get(vuln.reachability, 8.0)

    age_days = (dt.datetime.now(dt.timezone.utc) - vuln.discovered_at.replace(tzinfo=dt.timezone.utc)).days
    age_pts = min(age_days * 0.5, 20.0)

    score = severity_pts + cvss_pts + criticality_pts + reachability_pts + age_pts
    rationale = (
        f"severity={vuln.severity.value}({severity_pts:.1f}) "
        f"cvss={vuln.cvss_score or 0}({cvss_pts:.1f}) "
        f"asset_criticality={criticality}({criticality_pts:.1f}) "
        f"reachability={vuln.reachability.value}({reachability_pts:.1f}) "
        f"age_days={age_days}({age_pts:.1f})"
    )
    return round(score, 1), rationale


def days_overdue(vuln: Vulnerability, *, as_of: dt.datetime | None = None) -> int | None:
    """Days past due_date, or None if there's no due date or it's not yet due.
    Only meaningful for vulns still open/in-progress; callers should check status."""
    if vuln.due_date is None:
        return None
    now = as_of or dt.datetime.now(dt.timezone.utc)
    due = vuln.due_date if vuln.due_date.tzinfo else vuln.due_date.replace(tzinfo=dt.timezone.utc)
    delta = (now - due).days
    return delta if delta > 0 else None


def is_overdue(vuln: Vulnerability, *, as_of: dt.datetime | None = None) -> bool:
    return vuln.status in (VulnStatus.OPEN, VulnStatus.IN_PROGRESS) and days_overdue(vuln, as_of=as_of) is not None


def list_overdue_vulnerabilities(session: Session) -> list[Vulnerability]:
    """Open/in-progress vulnerabilities past their due_date, highest priority first."""
    now = dt.datetime.now(dt.timezone.utc)
    stmt = (
        select(Vulnerability)
        .where(
            Vulnerability.status.in_((VulnStatus.OPEN, VulnStatus.IN_PROGRESS)),
            Vulnerability.due_date.is_not(None),
            Vulnerability.due_date < now,
        )
        .order_by(Vulnerability.priority_score.desc().nulls_last())
    )
    return list(session.execute(stmt).scalars().all())


def set_priority(session: Session, vuln: Vulnerability, *, actor: str = "agent") -> float:
    score, rationale = compute_priority_score(vuln)
    vuln.priority_score = score
    vuln.priority_rationale = rationale
    add_timeline_event(
        session, vuln, event_type="priority_set", description=f"Priority score set to {score} ({rationale})", actor=actor
    )
    return score


# --- Remediation steps ---------------------------------------------------


def add_remediation_step(
    session: Session,
    vuln: Vulnerability,
    description: str,
    *,
    owner: Stakeholder | None = None,
    status: StepStatus = StepStatus.PLANNED,
) -> RemediationStep:
    step = RemediationStep(vulnerability=vuln, description=description, owner=owner, status=status)
    session.add(step)
    add_timeline_event(session, vuln, event_type="remediation_step_added", description=description)
    return step


def update_remediation_step_status(session: Session, step: RemediationStep, status: StepStatus, *, actor: str = "agent") -> None:
    step.status = status
    if status == StepStatus.COMPLETED:
        step.completed_at = dt.datetime.now(dt.timezone.utc)
    add_timeline_event(
        session,
        step.vulnerability,
        event_type="remediation_step_status",
        description=f"Step '{step.description}' -> {status.value}",
        actor=actor,
    )


# --- Communications & commitments ---------------------------------------------------


def log_communication(
    session: Session,
    vuln: Vulnerability,
    *,
    channel: CommChannel,
    body: str,
    direction: CommDirection = CommDirection.OUTBOUND,
    stakeholder: Stakeholder | None = None,
    subject: str = "",
    external_ref: str | None = None,
) -> CommunicationLog:
    log = CommunicationLog(
        vulnerability=vuln,
        channel=channel,
        direction=direction,
        stakeholder=stakeholder,
        subject=subject,
        body=body,
        external_ref=external_ref,
    )
    session.add(log)
    who = stakeholder.name if stakeholder else "unknown"
    add_timeline_event(
        session,
        vuln,
        event_type="communication",
        description=f"{direction.value} {channel.value} with {who}: {subject or body[:80]}",
    )
    return log


def add_commitment(
    session: Session,
    vuln: Vulnerability,
    description: str,
    committed_date: dt.datetime,
    *,
    stakeholder: Stakeholder | None = None,
) -> Commitment:
    commitment = Commitment(
        vulnerability=vuln, description=description, committed_date=committed_date, stakeholder=stakeholder
    )
    session.add(commitment)
    who = stakeholder.name if stakeholder else "unknown"
    add_timeline_event(
        session,
        vuln,
        event_type="commitment_made",
        description=f"{who} committed: {description} (by {committed_date.date()})",
    )
    return commitment


def update_commitment_status(session: Session, commitment: Commitment, status: CommitmentStatus) -> None:
    commitment.status = status
    add_timeline_event(
        session,
        commitment.vulnerability,
        event_type="commitment_status",
        description=f"Commitment '{commitment.description}' -> {status.value}",
    )


def list_commitments_due(session: Session, *, within_days: int = 3, status: CommitmentStatus = CommitmentStatus.OPEN) -> list[Commitment]:
    cutoff = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=within_days)
    stmt = select(Commitment).where(Commitment.status == status, Commitment.committed_date <= cutoff)
    return list(session.execute(stmt).scalars().all())


# --- External references (PRs, commits, tickets) ---------------------------------------------------


def add_external_reference(
    session: Session,
    vuln: Vulnerability,
    *,
    ref_type: RefType,
    external_id: str,
    url: str = "",
    status: str = "open",
) -> ExternalReference:
    ref = ExternalReference(vulnerability=vuln, ref_type=ref_type, external_id=external_id, url=url, status=status)
    session.add(ref)
    add_timeline_event(
        session, vuln, event_type=f"{ref_type.value}_linked", description=f"{ref_type.value} {external_id} ({status})"
    )
    return ref


def update_external_reference_status(session: Session, ref: ExternalReference, status: str) -> None:
    ref.status = status
    add_timeline_event(
        session,
        ref.vulnerability,
        event_type=f"{ref.ref_type.value}_status",
        description=f"{ref.ref_type.value} {ref.external_id} -> {status}",
    )


# --- Timeline ---------------------------------------------------


def add_timeline_event(
    session: Session, vuln: Vulnerability, *, event_type: str, description: str, actor: str = "agent"
) -> TimelineEvent:
    event = TimelineEvent(vulnerability=vuln, event_type=event_type, description=description, actor=actor)
    session.add(event)
    return event
