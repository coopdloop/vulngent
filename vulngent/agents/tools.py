"""Agent tools: plain functions wrapping the ledger + integrations.

Each tool opens its own short-lived DB session and returns a plain string (JSON for
structured data, prose for action confirmations) so results are easy for the model to
read. Docstrings double as the tool description shown to the LLM - keep them accurate.
"""

from __future__ import annotations

import datetime as dt
import json

from vulngent.db import repository as repo
from vulngent.db.models import (
    CommChannel,
    CommDirection,
    CommitmentStatus,
    Reachability,
    RefType,
    Severity,
    StepStatus,
    VulnStatus,
)
from vulngent.db.session import get_session
from vulngent.integrations.email_client import EmailClient, EmailNotConfigured
from vulngent.integrations.github_client import GitHubClient, GitHubNotConfigured
from vulngent.integrations.jira_client import JiraClient, JiraNotConfigured
from vulngent.integrations.slack_client import SlackClient, SlackNotConfigured


def _err(exc: Exception) -> str:
    return f"ERROR: {exc}"


# --- Lookup tools (used by every agent) ---------------------------------------------------


def list_open_vulnerabilities(min_priority: float = 0.0) -> str:
    """List open/in-progress vulnerabilities, ordered by priority score (highest first).
    Optionally filter to only those at or above min_priority. Returns a JSON list with
    id, external_id, title, severity, priority_score, reachability, and asset name."""
    with get_session() as session:
        vulns = repo.list_vulnerabilities(session, status=VulnStatus.OPEN) + repo.list_vulnerabilities(
            session, status=VulnStatus.IN_PROGRESS
        )
        out = [
            {
                "id": v.id,
                "external_id": v.external_id,
                "title": v.title,
                "severity": v.severity.value,
                "priority_score": v.priority_score,
                "reachability": v.reachability.value,
                "status": v.status.value,
                "asset": v.asset.name if v.asset else None,
            }
            for v in vulns
            if (v.priority_score or 0) >= min_priority
        ]
    return json.dumps(out, indent=2)


def find_low_hanging_fruit() -> str:
    """Find high-impact, easy wins: open vulnerabilities that are high/critical severity,
    confirmed reachable, and have no remediation steps recorded yet. These are the best
    candidates to fix first for the least effort. Returns a JSON list."""
    with get_session() as session:
        vulns = repo.list_vulnerabilities(session, status=VulnStatus.OPEN)
        candidates = [
            v
            for v in vulns
            if v.severity in (Severity.CRITICAL, Severity.HIGH)
            and v.reachability == Reachability.REACHABLE
            and len(v.remediation_steps) == 0
        ]
        out = [
            {"id": v.id, "external_id": v.external_id, "title": v.title, "severity": v.severity.value, "asset": v.asset.name if v.asset else None}
            for v in candidates
        ]
    return json.dumps(out, indent=2)


def get_vulnerability_detail(vuln_id: int) -> str:
    """Get full detail for one vulnerability: description, asset/owner, remediation steps,
    external references (PRs/commits/tickets), open commitments, and recent timeline events."""
    with get_session() as session:
        v = repo.get_vulnerability(session, vuln_id)
        if not v:
            return f"ERROR: no vulnerability with id {vuln_id}"
        out = {
            "id": v.id,
            "external_id": v.external_id,
            "title": v.title,
            "description": v.description,
            "severity": v.severity.value,
            "cvss_score": v.cvss_score,
            "status": v.status.value,
            "reachability": v.reachability.value,
            "priority_score": v.priority_score,
            "priority_rationale": v.priority_rationale,
            "asset": v.asset.name if v.asset else None,
            "repo_full_name": v.asset.repo_full_name if v.asset else None,
            "owner": v.asset.owner.name if v.asset and v.asset.owner else None,
            "owner_slack_id": v.asset.owner.slack_user_id if v.asset and v.asset.owner else None,
            "owner_email": v.asset.owner.email if v.asset and v.asset.owner else None,
            "remediation_steps": [
                {"id": s.id, "description": s.description, "status": s.status.value} for s in v.remediation_steps
            ],
            "external_references": [
                {"type": r.ref_type.value, "external_id": r.external_id, "url": r.url, "status": r.status}
                for r in v.external_refs
            ],
            "open_commitments": [
                {
                    "id": c.id,
                    "description": c.description,
                    "committed_date": c.committed_date.isoformat(),
                    "status": c.status.value,
                }
                for c in v.commitments
                if c.status == CommitmentStatus.OPEN
            ],
            "recent_timeline": [
                {"at": e.occurred_at.isoformat(), "type": e.event_type, "description": e.description}
                for e in v.timeline_events[-10:]
            ],
        }
    return json.dumps(out, indent=2)


def ask_security_analyst(vuln_id: int, question: str) -> str:
    """Ask the human security analyst a direct question (e.g. to confirm reachability
    analysis when the agent can't determine it alone) and return their answer. Use this
    sparingly - only when you genuinely need human judgment to proceed."""
    print(f"\n[agent question about vuln #{vuln_id}]: {question}")
    answer = input("your answer> ")
    return answer.strip() or "(no answer given)"


# --- Triage tools ---------------------------------------------------


def set_vulnerability_reachability(vuln_id: int, reachability: str, notes: str = "") -> str:
    """Set the reachability assessment for a vulnerability. reachability must be one of:
    unknown, pending_analyst, reachable, not_reachable. Include brief notes on why."""
    try:
        value = Reachability(reachability)
    except ValueError:
        return f"ERROR: invalid reachability '{reachability}'. Must be one of {[r.value for r in Reachability]}"
    with get_session() as session:
        v = repo.get_vulnerability(session, vuln_id)
        if not v:
            return f"ERROR: no vulnerability with id {vuln_id}"
        repo.set_reachability(session, v, value, notes=notes)
        score = repo.set_priority(session, v)
    return f"Reachability for #{vuln_id} set to {value.value}. Priority score recalculated to {score}."


def recompute_priority(vuln_id: int) -> str:
    """Recompute and store the priority score for a vulnerability from its current
    severity, CVSS, asset criticality, reachability, and age."""
    with get_session() as session:
        v = repo.get_vulnerability(session, vuln_id)
        if not v:
            return f"ERROR: no vulnerability with id {vuln_id}"
        score = repo.set_priority(session, v)
        rationale = v.priority_rationale
    return f"Priority score for #{vuln_id}: {score} ({rationale})"


def set_vulnerability_status(vuln_id: int, status: str) -> str:
    """Set the overall status of a vulnerability. status must be one of: open,
    in_progress, remediated, risk_accepted, false_positive."""
    try:
        value = VulnStatus(status)
    except ValueError:
        return f"ERROR: invalid status '{status}'. Must be one of {[s.value for s in VulnStatus]}"
    with get_session() as session:
        v = repo.get_vulnerability(session, vuln_id)
        if not v:
            return f"ERROR: no vulnerability with id {vuln_id}"
        repo.set_vulnerability_status(session, v, value)
    return f"Vulnerability #{vuln_id} status set to {value.value}."


# --- Outreach tools ---------------------------------------------------


def send_slack_update(vuln_id: int, message: str, to_user_slack_id: str = "") -> str:
    """Send a Slack message about a vulnerability. If to_user_slack_id is given, DM that
    user; otherwise post to the default configured channel. Logs the communication and a
    timeline event either way."""
    with get_session() as session:
        v = repo.get_vulnerability(session, vuln_id)
        if not v:
            return f"ERROR: no vulnerability with id {vuln_id}"
        owner = v.asset.owner if v.asset else None
        try:
            client = SlackClient()
            if to_user_slack_id:
                ts = client.send_dm(to_user_slack_id, message)
            else:
                from vulngent.config import get_settings

                channel = get_settings().slack_default_channel
                if not channel:
                    return "ERROR: no to_user_slack_id given and SLACK_DEFAULT_CHANNEL is not set."
                ts = client.send_message(channel, message)
        except (SlackNotConfigured, RuntimeError) as exc:
            return _err(exc)
        repo.log_communication(
            session, v, channel=CommChannel.SLACK, body=message, stakeholder=owner, external_ref=ts
        )
    return f"Slack message sent for #{vuln_id} (ts={ts})."


def send_email_update(vuln_id: int, to_address: str, subject: str, body: str) -> str:
    """Send an email about a vulnerability to an external service owner. Logs the
    communication and a timeline event."""
    with get_session() as session:
        v = repo.get_vulnerability(session, vuln_id)
        if not v:
            return f"ERROR: no vulnerability with id {vuln_id}"
        owner = v.asset.owner if v.asset else None
        try:
            EmailClient().send_email(to_address, subject, body)
        except EmailNotConfigured as exc:
            return _err(exc)
        repo.log_communication(
            session, v, channel=CommChannel.EMAIL, body=body, subject=subject, stakeholder=owner
        )
    return f"Email sent for #{vuln_id} to {to_address}."


def get_communication_history(vuln_id: int) -> str:
    """Get the full outbound/inbound communication history logged for a vulnerability."""
    with get_session() as session:
        v = repo.get_vulnerability(session, vuln_id)
        if not v:
            return f"ERROR: no vulnerability with id {vuln_id}"
        out = [
            {
                "at": c.sent_at.isoformat(),
                "channel": c.channel.value,
                "direction": c.direction.value,
                "subject": c.subject,
                "body": c.body,
            }
            for c in v.communications
        ]
    return json.dumps(out, indent=2)


def record_inbound_reply(vuln_id: int, channel: str, body: str) -> str:
    """Record an inbound reply received from a stakeholder (e.g. paraphrased from Slack/
    email/GitHub) about a vulnerability, so it's part of the ledger's history."""
    try:
        chan = CommChannel(channel)
    except ValueError:
        return f"ERROR: invalid channel '{channel}'. Must be one of {[c.value for c in CommChannel]}"
    with get_session() as session:
        v = repo.get_vulnerability(session, vuln_id)
        if not v:
            return f"ERROR: no vulnerability with id {vuln_id}"
        owner = v.asset.owner if v.asset else None
        repo.log_communication(session, v, channel=chan, body=body, direction=CommDirection.INBOUND, stakeholder=owner)
    return f"Inbound reply recorded for #{vuln_id}."


def record_commitment(vuln_id: int, description: str, committed_date: str) -> str:
    """Record a stakeholder's remediation commitment for a vulnerability, e.g. 'will ship
    the patch'. committed_date must be an ISO date, e.g. '2026-09-12'."""
    try:
        due = dt.datetime.fromisoformat(committed_date).replace(tzinfo=dt.timezone.utc)
    except ValueError:
        return f"ERROR: could not parse committed_date '{committed_date}' (expected YYYY-MM-DD)."
    with get_session() as session:
        v = repo.get_vulnerability(session, vuln_id)
        if not v:
            return f"ERROR: no vulnerability with id {vuln_id}"
        owner = v.asset.owner if v.asset else None
        repo.add_commitment(session, v, description, due, stakeholder=owner)
    return f"Commitment recorded for #{vuln_id}: '{description}' by {due.date()}."


def list_commitments_due_soon(within_days: int = 3) -> str:
    """List open commitments due within the given number of days (for follow-up outreach)."""
    with get_session() as session:
        commitments = repo.list_commitments_due(session, within_days=within_days)
        out = [
            {
                "id": c.id,
                "vulnerability_id": c.vulnerability_id,
                "description": c.description,
                "committed_date": c.committed_date.isoformat(),
                "stakeholder": c.stakeholder.name if c.stakeholder else None,
            }
            for c in commitments
        ]
    return json.dumps(out, indent=2)


def update_commitment_status(commitment_id: int, status: str) -> str:
    """Update a commitment's status: open, met, missed, or renegotiated."""
    try:
        value = CommitmentStatus(status)
    except ValueError:
        return f"ERROR: invalid status '{status}'. Must be one of {[s.value for s in CommitmentStatus]}"
    with get_session() as session:
        from vulngent.db.models import Commitment

        c = session.get(Commitment, commitment_id)
        if not c:
            return f"ERROR: no commitment with id {commitment_id}"
        repo.update_commitment_status(session, c, value)
    return f"Commitment #{commitment_id} status set to {value.value}."


# --- Tracker tools ---------------------------------------------------


def add_remediation_step(vuln_id: int, description: str) -> str:
    """Add a planned remediation step to a vulnerability's ledger (e.g. 'upgrade libfoo to
    2.3.1', 'add input validation on /api/upload')."""
    with get_session() as session:
        v = repo.get_vulnerability(session, vuln_id)
        if not v:
            return f"ERROR: no vulnerability with id {vuln_id}"
        step = repo.add_remediation_step(session, v, description)
        session.flush()
        step_id = step.id
    return f"Remediation step #{step_id} added to #{vuln_id}."


def update_remediation_step_status(step_id: int, status: str) -> str:
    """Update a remediation step's status: planned, in_progress, completed, or blocked."""
    try:
        value = StepStatus(status)
    except ValueError:
        return f"ERROR: invalid status '{status}'. Must be one of {[s.value for s in StepStatus]}"
    with get_session() as session:
        from vulngent.db.models import RemediationStep

        step = session.get(RemediationStep, step_id)
        if not step:
            return f"ERROR: no remediation step with id {step_id}"
        repo.update_remediation_step_status(session, step, value)
    return f"Remediation step #{step_id} status set to {value.value}."


def create_github_issue_for_vuln(vuln_id: int, repo_full_name: str = "") -> str:
    """Create a GitHub issue to track remediation of a vulnerability, in the given repo
    (org/repo). If repo_full_name is omitted, uses the vulnerability's asset repo."""
    with get_session() as session:
        v = repo.get_vulnerability(session, vuln_id)
        if not v:
            return f"ERROR: no vulnerability with id {vuln_id}"
        target_repo = repo_full_name or (v.asset.repo_full_name if v.asset else None)
        if not target_repo:
            return "ERROR: no repo_full_name given and asset has no linked repo."
        try:
            issue_url = GitHubClient().create_issue(
                target_repo,
                title=f"[{v.severity.value.upper()}] {v.external_id}: {v.title}",
                body=v.description or "(no description)",
                labels=["security", v.severity.value],
            )
        except GitHubNotConfigured as exc:
            return _err(exc)
        repo.add_external_reference(session, v, ref_type=RefType.GITHUB_ISSUE, external_id=issue_url, url=issue_url)
    return f"GitHub issue created for #{vuln_id}: {issue_url}"


def link_github_prs_and_commits(vuln_id: int) -> str:
    """Search the vulnerability's linked GitHub repo for PRs and commits that reference
    its external_id (e.g. the CVE id) and link any newly found ones into the ledger."""
    with get_session() as session:
        v = repo.get_vulnerability(session, vuln_id)
        if not v:
            return f"ERROR: no vulnerability with id {vuln_id}"
        target_repo = v.asset.repo_full_name if v.asset else None
        if not target_repo:
            return "ERROR: vulnerability's asset has no linked GitHub repo."
        already = {r.external_id for r in v.external_refs}
        try:
            client = GitHubClient()
            prs = client.find_prs_referencing(target_repo, v.external_id)
            commits = client.find_commits_referencing(target_repo, v.external_id)
        except GitHubNotConfigured as exc:
            return _err(exc)

        added = []
        for pr in prs:
            ext_id = f"{target_repo}#{pr.number}"
            if ext_id in already:
                continue
            status = "merged" if pr.merged else pr.state
            repo.add_external_reference(session, v, ref_type=RefType.GITHUB_PR, external_id=ext_id, url=pr.url, status=status)
            added.append(ext_id)
        for c in commits:
            if c.sha in already:
                continue
            repo.add_external_reference(session, v, ref_type=RefType.GITHUB_COMMIT, external_id=c.sha, url=c.url, status="committed")
            added.append(c.sha)
    if not added:
        return f"No new PRs/commits found referencing {v.external_id} in {target_repo}."
    return f"Linked {len(added)} new reference(s) to #{vuln_id}: {', '.join(added)}"


def sync_jira_ticket(vuln_id: int, project_key: str = "") -> str:
    """Create a Jira ticket for this vulnerability if one doesn't exist yet, or refresh
    the status of the existing one. project_key overrides the default JIRA_PROJECT_KEY."""
    with get_session() as session:
        v = repo.get_vulnerability(session, vuln_id)
        if not v:
            return f"ERROR: no vulnerability with id {vuln_id}"
        existing = next((r for r in v.external_refs if r.ref_type == RefType.JIRA_TICKET), None)
        try:
            client = JiraClient()
            if existing:
                status = client.get_status(existing.external_id)
                repo.update_external_reference_status(session, existing, status)
                return f"Jira ticket {existing.external_id} status refreshed: {status}"
            key = client.create_issue(
                summary=f"[{v.severity.value.upper()}] {v.external_id}: {v.title}",
                description=v.description or "(no description)",
                project_key=project_key or None,
            )
        except JiraNotConfigured as exc:
            return _err(exc)
        from vulngent.config import get_settings

        jira_server = get_settings().jira_server
        repo.add_external_reference(session, v, ref_type=RefType.JIRA_TICKET, external_id=key, url=f"{jira_server}/browse/{key}")
    return f"Jira ticket {key} created for #{vuln_id}."


def generate_status_report() -> str:
    """Generate a markdown status report across the whole ledger: counts by status and
    severity, the current top-priority open vulnerabilities, and any commitments due
    soon or already missed."""
    with get_session() as session:
        open_vulns = repo.list_vulnerabilities(session, status=VulnStatus.OPEN)
        in_progress = repo.list_vulnerabilities(session, status=VulnStatus.IN_PROGRESS)
        due_soon = repo.list_commitments_due(session, within_days=3)

        by_severity: dict[str, int] = {}
        for v in open_vulns + in_progress:
            by_severity[v.severity.value] = by_severity.get(v.severity.value, 0) + 1

        top = sorted(open_vulns + in_progress, key=lambda v: v.priority_score or 0, reverse=True)[:10]

        lines = ["# vulngent status report", ""]
        lines.append(f"Open: {len(open_vulns)}  In progress: {len(in_progress)}")
        lines.append("")
        lines.append("## By severity")
        for sev, count in sorted(by_severity.items()):
            lines.append(f"- {sev}: {count}")
        lines.append("")
        lines.append("## Top priority")
        for v in top:
            lines.append(f"- #{v.id} [{v.severity.value}] {v.external_id} — {v.title} (score={v.priority_score})")
        lines.append("")
        lines.append("## Commitments due within 3 days")
        for c in due_soon:
            lines.append(f"- vuln #{c.vulnerability_id}: {c.description} (due {c.committed_date.date()})")
        report = "\n".join(lines)
    return report
