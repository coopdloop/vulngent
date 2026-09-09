"""GitHub integration: issues, PR/commit lookup for remediation tracking."""

from __future__ import annotations

import re
from dataclasses import dataclass

from github import Auth, Github

from vulngent.config import get_settings


class GitHubNotConfigured(RuntimeError):
    pass


_REPO_URL_RE = re.compile(
    r"^(?:https?://)?(?:www\.)?github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+?)(?:\.git)?/?$"
)
_REPO_SSH_RE = re.compile(r"^git@github\.com:(?P<owner>[^/]+)/(?P<repo>[^/]+?)(?:\.git)?/?$")


def parse_repo_full_name(value: str) -> str:
    """Normalize a GitHub repo reference to 'owner/repo'. Accepts an existing
    'owner/repo' slug as-is, or a full/partial GitHub URL in any common form:
    https://github.com/owner/repo, https://github.com/owner/repo.git,
    git@github.com:owner/repo.git, github.com/owner/repo."""
    value = value.strip()
    for pattern in (_REPO_URL_RE, _REPO_SSH_RE):
        match = pattern.match(value)
        if match:
            return f"{match.group('owner')}/{match.group('repo')}"
    if re.fullmatch(r"[^/\s@:]+/[^/\s@:]+", value):
        return value
    raise ValueError(
        f"Could not parse '{value}' as a GitHub repo. Expected 'owner/repo' or a github.com URL."
    )


@dataclass
class PullRequestInfo:
    number: int
    title: str
    url: str
    state: str  # "open" | "closed"
    merged: bool


@dataclass
class CommitInfo:
    sha: str
    message: str
    url: str
    author: str | None


class GitHubClient:
    def __init__(self, token: str | None = None) -> None:
        settings = get_settings()
        token = token or settings.github_token
        if not token:
            raise GitHubNotConfigured("GITHUB_TOKEN is not set.")
        self._gh = Github(auth=Auth.Token(token))

    def create_issue(self, repo_full_name: str, title: str, body: str, labels: list[str] | None = None) -> str:
        repository = self._gh.get_repo(repo_full_name)
        issue = repository.create_issue(title=title, body=body, labels=labels or [])
        return issue.html_url

    def comment_on_issue(self, repo_full_name: str, issue_number: int, body: str) -> str:
        repository = self._gh.get_repo(repo_full_name)
        issue = repository.get_issue(issue_number)
        comment = issue.create_comment(body)
        return comment.html_url

    def find_prs_referencing(self, repo_full_name: str, query_text: str) -> list[PullRequestInfo]:
        """Search PRs (open or closed) in this repo whose title/body mentions query_text
        (typically a CVE id or vuln external_id)."""
        query = f'repo:{repo_full_name} type:pr "{query_text}"'
        results = self._gh.search_issues(query)
        prs: list[PullRequestInfo] = []
        for item in results:
            prs.append(
                PullRequestInfo(
                    number=item.number,
                    title=item.title,
                    url=item.html_url,
                    state=item.state,
                    merged=item.pull_request is not None and item.pull_request.merged_at is not None,
                )
            )
        return prs

    def find_commits_referencing(self, repo_full_name: str, query_text: str) -> list[CommitInfo]:
        """Search commit messages in this repo for query_text."""
        query = f'repo:{repo_full_name} "{query_text}"'
        results = self._gh.search_commits(query)
        commits: list[CommitInfo] = []
        for item in results:
            commits.append(
                CommitInfo(
                    sha=item.sha,
                    message=item.commit.message,
                    url=item.html_url,
                    author=item.commit.author.name if item.commit.author else None,
                )
            )
        return commits

    def get_pr_status(self, repo_full_name: str, pr_number: int) -> PullRequestInfo:
        pr = self._gh.get_repo(repo_full_name).get_pull(pr_number)
        return PullRequestInfo(number=pr.number, title=pr.title, url=pr.html_url, state=pr.state, merged=pr.merged)
