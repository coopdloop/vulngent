"""Settings UI backend: view/edit .env configuration and test integrations.

The schema is declared here (not in the frontend) so .env stays the source of
truth and new settings only need a schema entry to show up in the UI."""

from __future__ import annotations

import asyncio
import re
from pathlib import Path
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel

from vulngent.config import get_settings

router = APIRouter(prefix="/api/settings", tags=["settings"])

ENV_PATH = Path(".env")

MODEL_SUGGESTIONS = [
    "anthropic/claude-sonnet-4.5",
    "anthropic/claude-haiku-4.5",
    "anthropic/claude-opus-4.1",
    "openai/gpt-4o",
    "openai/gpt-4o-mini",
    "google/gemini-2.5-pro",
    "deepseek/deepseek-chat",
    "meta-llama/llama-3.3-70b-instruct",
]

SETTINGS_GROUPS: list[dict[str, Any]] = [
    {
        "id": "llm",
        "title": "LLM backend",
        "description": "Which model the agents run on (via OpenRouter's OpenAI-compatible endpoint).",
        "fields": [
            {"key": "OPENROUTER_API_KEY", "label": "API key", "secret": True, "hint": "openrouter.ai/keys"},
            {"key": "OPENROUTER_BASE_URL", "label": "Base URL", "hint": "OpenAI-compatible endpoint"},
            {"key": "OPENROUTER_MODEL", "label": "Model", "options": "models", "hint": "Applies to new chat sessions"},
        ],
    },
    {
        "id": "database",
        "title": "Database",
        "description": "SQLAlchemy URL. SQLite by default; Postgres etc. works unchanged.",
        "fields": [
            {"key": "DATABASE_URL", "label": "Database URL", "hint": "sqlite:///./vulngent.db"},
        ],
    },
    {
        "id": "github",
        "title": "GitHub",
        "description": "Issues, PR/commit tracking against remediation work.",
        "fields": [
            {"key": "GITHUB_TOKEN", "label": "Token", "secret": True, "hint": "Personal access token with repo scope"},
        ],
    },
    {
        "id": "slack",
        "title": "Slack",
        "description": "Stakeholder outreach and notifications.",
        "fields": [
            {"key": "SLACK_BOT_TOKEN", "label": "Bot token", "secret": True, "hint": "xoxb-…"},
            {"key": "SLACK_DEFAULT_CHANNEL", "label": "Default channel", "hint": "e.g. #security or a channel ID"},
        ],
    },
    {
        "id": "email",
        "title": "Email (SMTP)",
        "description": "Outreach over plain SMTP, alternative to Slack.",
        "fields": [
            {"key": "SMTP_HOST", "label": "Host"},
            {"key": "SMTP_PORT", "label": "Port", "type": "number"},
            {"key": "SMTP_USERNAME", "label": "Username"},
            {"key": "SMTP_PASSWORD", "label": "Password", "secret": True},
            {"key": "SMTP_FROM_ADDRESS", "label": "From address"},
            {"key": "SMTP_USE_TLS", "label": "Use TLS", "type": "bool"},
        ],
    },
    {
        "id": "jira",
        "title": "Jira",
        "description": "Sync remediation work with Jira tickets.",
        "fields": [
            {"key": "JIRA_SERVER", "label": "Server URL", "hint": "https://your-org.atlassian.net"},
            {"key": "JIRA_EMAIL", "label": "Account email"},
            {"key": "JIRA_API_TOKEN", "label": "API token", "secret": True},
            {"key": "JIRA_PROJECT_KEY", "label": "Project key", "hint": "e.g. SEC"},
        ],
    },
    {
        "id": "whitelabel",
        "title": "Report whitelabeling",
        "description": "Branding applied to PDF/DOCX exports from the Reports view.",
        "fields": [
            {"key": "REPORT_COMPANY_NAME", "label": "Company name"},
            {"key": "REPORT_TITLE", "label": "Report title"},
            {"key": "REPORT_LOGO_PATH", "label": "Logo path", "hint": "Filesystem path to a PNG/JPG"},
            {"key": "REPORT_PRIMARY_COLOR", "label": "Primary color", "type": "color"},
            {"key": "REPORT_ACCENT_COLOR", "label": "Accent color", "type": "color"},
            {"key": "REPORT_FOOTER_TEXT", "label": "Footer text"},
        ],
    },
]

_FIELD_TO_ATTR = {f["key"]: f["key"].lower() for g in SETTINGS_GROUPS for f in g["fields"]}


@router.get("")
async def read_settings() -> dict[str, Any]:
    settings = get_settings()
    groups = []
    for group in SETTINGS_GROUPS:
        fields = [
            {
                **{k: v for k, v in field.items() if k != "options"},
                "value": str(getattr(settings, _FIELD_TO_ATTR[field["key"]], "")),
            }
            for field in group["fields"]
        ]
        groups.append({**group, "fields": fields})
    return {
        "groups": groups,
        "env_file": str(ENV_PATH),
        "env_file_exists": ENV_PATH.exists(),
        "model_suggestions": MODEL_SUGGESTIONS,
    }


class SettingsUpdate(BaseModel):
    values: dict[str, str]


@router.put("")
async def update_settings(body: SettingsUpdate) -> dict[str, Any]:
    unknown = sorted(k for k in body.values if k not in _FIELD_TO_ATTR)
    if unknown:
        return {"ok": False, "error": f"Unknown setting keys: {', '.join(unknown)}"}
    _write_env(body.values)
    get_settings.cache_clear()
    return {"ok": True}


_ENV_KEY_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=")


def _format_env_value(value: str) -> str:
    if not value:
        return ""
    if re.search(r"[\s#'\"]", value):
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    return value


def _write_env(updates: dict[str, str]) -> None:
    lines = ENV_PATH.read_text().splitlines() if ENV_PATH.exists() else []
    remaining = dict(updates)
    out: list[str] = []
    for line in lines:
        match = _ENV_KEY_RE.match(line)
        if match and not line.lstrip().startswith("#") and match.group(1) in remaining:
            out.append(f"{match.group(1)}={_format_env_value(remaining.pop(match.group(1)))}")
        else:
            out.append(line)
    if remaining:
        if out and out[-1].strip():
            out.append("")
        for key, value in remaining.items():
            out.append(f"{key}={_format_env_value(value)}")
    ENV_PATH.write_text("\n".join(out) + "\n")


# --- Integration tests ----------------------------------------------------


class SlackTestRequest(BaseModel):
    channel: str | None = None
    message: str | None = None


@router.post("/test/slack")
async def test_slack(body: SlackTestRequest) -> dict[str, Any]:
    return await asyncio.to_thread(_run_slack_test, body)


def _run_slack_test(body: SlackTestRequest) -> dict[str, Any]:
    from slack_sdk import WebClient
    from slack_sdk.errors import SlackApiError

    settings = get_settings()
    if not settings.slack_bot_token:
        return {"ok": False, "error": "SLACK_BOT_TOKEN is not set."}
    client = WebClient(token=settings.slack_bot_token)
    try:
        auth = client.auth_test()
    except SlackApiError as exc:
        return {"ok": False, "error": f"auth.test failed: {exc.response.get('error', exc)}"}
    result: dict[str, Any] = {
        "ok": True,
        "team": auth.get("team"),
        "bot": auth.get("user"),
        "bot_id": auth.get("user_id"),
        "sent": None,
    }
    channel = (body.channel or settings.slack_default_channel or "").strip()
    if channel:
        message = (body.message or "").strip() or _default_slack_preview(settings)
        try:
            resp = client.chat_postMessage(channel=channel, text=message)
            result["sent"] = {"channel": channel, "message": message, "ts": resp["ts"]}
        except SlackApiError as exc:
            result["ok"] = False
            result["error"] = f"Posting to {channel} failed: {exc.response.get('error', exc)}"
    return result


def _default_slack_preview(settings: Any) -> str:
    return (
        f":shield: *{settings.report_company_name}* test notification\n"
        "Your Slack integration is wired up. The outreach agent sends stakeholder "
        "updates, commitment follow-ups, and status pings to this channel."
    )


class GitHubTestRequest(BaseModel):
    repo: str | None = None


@router.post("/test/github")
async def test_github(body: GitHubTestRequest) -> dict[str, Any]:
    return await asyncio.to_thread(_run_github_test, body)


def _run_github_test(body: GitHubTestRequest) -> dict[str, Any]:
    from github import Auth, Github, GithubException

    from vulngent.integrations.github_client import parse_repo_full_name

    settings = get_settings()
    if not settings.github_token:
        return {"ok": False, "error": "GITHUB_TOKEN is not set."}
    gh = Github(auth=Auth.Token(settings.github_token), timeout=15)
    try:
        user = gh.get_user()
        login = user.login
    except GithubException as exc:
        return {"ok": False, "error": f"Token check failed: {exc.data.get('message', exc)}"}
    result: dict[str, Any] = {"ok": True, "login": login, "repo": None}
    repo_ref = (body.repo or "").strip()
    if repo_ref:
        try:
            full_name = parse_repo_full_name(repo_ref)
            repo = gh.get_repo(full_name)
            perms = repo.permissions or {}
            result["repo"] = {
                "full_name": repo.full_name,
                "private": repo.private,
                "permissions": {
                    "pull": bool(getattr(perms, "pull", False)),
                    "push": bool(getattr(perms, "push", False)),
                    "admin": bool(getattr(perms, "admin", False)),
                },
                "issues_url": repo.html_url + "/issues",
            }
        except ValueError as exc:
            result["ok"] = False
            result["error"] = str(exc)
        except GithubException as exc:
            result["ok"] = False
            result["error"] = f"Repo check failed: {exc.data.get('message', exc)}"
    return result
