"""Jira integration: the project-management system of record for remediation tickets."""

from __future__ import annotations

from jira import JIRA

from vulngent.config import get_settings


class JiraNotConfigured(RuntimeError):
    pass


class JiraClient:
    def __init__(self) -> None:
        settings = get_settings()
        if not (settings.jira_server and settings.jira_email and settings.jira_api_token):
            raise JiraNotConfigured("JIRA_SERVER / JIRA_EMAIL / JIRA_API_TOKEN are not set.")
        self._settings = settings
        self._client = JIRA(server=settings.jira_server, basic_auth=(settings.jira_email, settings.jira_api_token))

    def create_issue(
        self,
        summary: str,
        description: str,
        *,
        project_key: str | None = None,
        issue_type: str = "Bug",
        labels: list[str] | None = None,
    ) -> str:
        project_key = project_key or self._settings.jira_project_key
        if not project_key:
            raise JiraNotConfigured("No Jira project key given (set JIRA_PROJECT_KEY or pass project_key).")
        issue = self._client.create_issue(
            fields={
                "project": {"key": project_key},
                "summary": summary,
                "description": description,
                "issuetype": {"name": issue_type},
                "labels": labels or [],
            }
        )
        return issue.key

    def add_comment(self, issue_key: str, body: str) -> None:
        self._client.add_comment(issue_key, body)

    def get_status(self, issue_key: str) -> str:
        issue = self._client.issue(issue_key)
        return issue.fields.status.name

    def transition_issue(self, issue_key: str, transition_name: str) -> None:
        issue = self._client.issue(issue_key)
        transitions = self._client.transitions(issue)
        match = next((t for t in transitions if t["name"].lower() == transition_name.lower()), None)
        if not match:
            available = ", ".join(t["name"] for t in transitions)
            raise ValueError(f"No transition '{transition_name}' available for {issue_key}. Available: {available}")
        self._client.transition_issue(issue, match["id"])
