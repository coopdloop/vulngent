"""Agent usage, cost and value analytics.

Token usage is already captured per assistant turn in the persisted chat payloads
(`ChatMessage.payload["usage"]`), so this reads the ledger's own history rather than
requiring a separate metering pipeline. Cost is priced from Settings (AGENT_COST_*),
and "value" is the analyst time the agents displaced — write actions they executed
and questions they answered — valued at the configured analyst rate.

Parallel to report_data.py: a plain dataclass snapshot the renderers and the
/api/usage endpoint both work off, so the dashboard and the PDF can't drift.
"""

from __future__ import annotations

import datetime as dt
import json
from collections import defaultdict
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from vulngent.config import get_settings
from vulngent.db.models import (
    ChatMessage,
    Commitment,
    CommunicationLog,
    ExternalReference,
    RemediationStep,
    TimelineEvent,
)
from vulngent.report_data import Branding

#: Tools that change the ledger or reach out to a human. Mirrors the confirmation-gated
#: write registry in chat/server.py; kept here so analytics doesn't import the server.
#: `plan_write_action` is deliberately excluded — it only stages a confirmation, and the
#: executed tool is persisted under its real name, so counting both double-counts.
WRITE_TOOL_NAMES = frozenset(
    {
        "create_github_issue_for_vuln",
        "send_slack_update",
        "send_email_update",
        "record_inbound_reply",
        "record_commitment",
        "update_commitment_status",
        "add_remediation_step",
        "update_remediation_step_status",
        "set_vulnerability_status",
        "set_vulnerability_reachability",
        "link_github_prs_and_commits",
        "sync_jira_ticket",
    }
)


@dataclass
class ModelUsage:
    model: str
    turns: int
    input_tokens: int
    output_tokens: int
    cost_usd: float

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens


@dataclass
class ToolUsage:
    name: str
    calls: int
    errors: int
    is_write: bool

    @property
    def error_rate(self) -> float:
        return (self.errors / self.calls) if self.calls else 0.0


@dataclass
class DailyUsage:
    day: dt.date
    turns: int
    input_tokens: int
    output_tokens: int
    cost_usd: float

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens


@dataclass
class ValueSummary:
    """Cost/value model. Deliberately transparent and assumption-driven — the rates
    live in Settings so a team can tune them rather than trust a black box."""

    actions_automated: int
    questions_answered: int
    analyst_minutes_saved: float
    analyst_hourly_rate: float
    labor_value_usd: float
    agent_cost_usd: float

    @property
    def analyst_hours_saved(self) -> float:
        return self.analyst_minutes_saved / 60.0

    @property
    def net_value_usd(self) -> float:
        return self.labor_value_usd - self.agent_cost_usd

    @property
    def roi_multiple(self) -> float | None:
        return (self.labor_value_usd / self.agent_cost_usd) if self.agent_cost_usd > 0 else None


@dataclass
class UsageReportData:
    generated_at: dt.datetime
    window_days: int | None
    since: dt.datetime | None
    turns: int
    sessions: int
    input_tokens: int
    output_tokens: int
    cost_usd: float
    tool_calls: int
    tool_errors: int
    by_model: list[ModelUsage]
    by_tool: list[ToolUsage]
    daily: list[DailyUsage]
    ledger_outcomes: dict[str, int]
    value: ValueSummary
    pricing: dict[str, float]
    branding: Branding = field(default_factory=Branding.from_settings)

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    @property
    def cost_per_turn(self) -> float:
        return (self.cost_usd / self.turns) if self.turns else 0.0

    @property
    def window_label(self) -> str:
        return f"last {self.window_days} days" if self.window_days else "all time"


def _aware(value: dt.datetime | None) -> dt.datetime | None:
    """SQLite hands back naive datetimes even for timezone=True columns."""
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=dt.timezone.utc)


def _price(input_tokens: int, output_tokens: int, rates: dict[str, float]) -> float:
    return (
        input_tokens / 1_000_000 * rates["input_per_mtok"]
        + output_tokens / 1_000_000 * rates["output_per_mtok"]
    )


def _count_since(session: Session, column, since: dt.datetime | None) -> int:
    stmt = select(column)
    if since is not None:
        stmt = stmt.where(column >= since)
    return len(session.execute(stmt).scalars().all())


def collect_usage_data(session: Session, *, window_days: int | None = 30) -> UsageReportData:
    """Aggregate agent usage/cost/value. `window_days=None` (or 0) means all time."""
    settings = get_settings()
    now = dt.datetime.now(dt.timezone.utc)
    window = window_days or None
    since = now - dt.timedelta(days=window) if window else None
    rates = {
        "input_per_mtok": settings.agent_cost_input_per_mtok,
        "output_per_mtok": settings.agent_cost_output_per_mtok,
    }

    stmt = select(ChatMessage).where(ChatMessage.role == "assistant")
    if since is not None:
        stmt = stmt.where(ChatMessage.created_at >= since)
    messages = session.execute(stmt).scalars().all()

    turns = 0
    sessions: set[str] = set()
    total_in = total_out = 0
    tool_calls = tool_errors = 0
    actions_automated = 0
    questions_answered = 0
    model_acc: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0])  # turns, in, out
    tool_acc: dict[str, list[int]] = defaultdict(lambda: [0, 0])  # calls, errors
    day_acc: dict[dt.date, list[int]] = defaultdict(lambda: [0, 0, 0])  # turns, in, out

    for message in messages:
        try:
            payload = json.loads(message.payload)
        except (json.JSONDecodeError, TypeError):
            continue
        turns += 1
        sessions.add(message.thread_id)
        usage = payload.get("usage") or {}
        in_tok = int(usage.get("input_tokens") or 0)
        out_tok = int(usage.get("output_tokens") or 0)
        model = usage.get("model") or settings.openrouter_model or "unknown"
        total_in += in_tok
        total_out += out_tok

        acc = model_acc[model]
        acc[0] += 1
        acc[1] += in_tok
        acc[2] += out_tok

        created = _aware(message.created_at) or now
        day = day_acc[created.date()]
        day[0] += 1
        day[1] += in_tok
        day[2] += out_tok

        wrote = False
        for call in payload.get("tool_calls") or []:
            name = str(call.get("name") or "unknown")
            is_error = bool(call.get("is_error"))
            tool_calls += 1
            tool_errors += int(is_error)
            entry = tool_acc[name]
            entry[0] += 1
            entry[1] += int(is_error)
            if name in WRITE_TOOL_NAMES and not is_error:
                actions_automated += 1
                wrote = True
        if not wrote:
            questions_answered += 1

    cost_usd = _price(total_in, total_out, rates)
    minutes_saved = (
        actions_automated * settings.agent_minutes_per_action
        + questions_answered * settings.agent_minutes_per_answer
    )
    value = ValueSummary(
        actions_automated=actions_automated,
        questions_answered=questions_answered,
        analyst_minutes_saved=minutes_saved,
        analyst_hourly_rate=settings.agent_analyst_hourly_rate,
        labor_value_usd=minutes_saved / 60.0 * settings.agent_analyst_hourly_rate,
        agent_cost_usd=cost_usd,
    )

    remediated_stmt = select(TimelineEvent).where(
        TimelineEvent.event_type == "status_change",
        TimelineEvent.description.like("%-> remediated%"),
    )
    if since is not None:
        remediated_stmt = remediated_stmt.where(TimelineEvent.occurred_at >= since)
    ledger_outcomes = {
        "vulns_remediated": len(session.execute(remediated_stmt).scalars().all()),
        "communications_logged": _count_since(session, CommunicationLog.sent_at, since),
        "commitments_recorded": _count_since(session, Commitment.created_at, since),
        "remediation_steps_added": _count_since(session, RemediationStep.created_at, since),
        "external_refs_linked": _count_since(session, ExternalReference.created_at, since),
        "timeline_events": _count_since(session, TimelineEvent.occurred_at, since),
    }

    by_model = sorted(
        (
            ModelUsage(model=m, turns=v[0], input_tokens=v[1], output_tokens=v[2], cost_usd=_price(v[1], v[2], rates))
            for m, v in model_acc.items()
        ),
        key=lambda m: m.cost_usd,
        reverse=True,
    )
    by_tool = sorted(
        (
            ToolUsage(name=n, calls=v[0], errors=v[1], is_write=n in WRITE_TOOL_NAMES)
            for n, v in tool_acc.items()
        ),
        key=lambda t: t.calls,
        reverse=True,
    )
    daily = [
        DailyUsage(day=d, turns=v[0], input_tokens=v[1], output_tokens=v[2], cost_usd=_price(v[1], v[2], rates))
        for d, v in sorted(day_acc.items())
    ]

    return UsageReportData(
        generated_at=now,
        window_days=window,
        since=since,
        turns=turns,
        sessions=len(sessions),
        input_tokens=total_in,
        output_tokens=total_out,
        cost_usd=cost_usd,
        tool_calls=tool_calls,
        tool_errors=tool_errors,
        by_model=by_model,
        by_tool=by_tool,
        daily=daily,
        ledger_outcomes=ledger_outcomes,
        value=value,
        pricing={
            **rates,
            "analyst_hourly_rate": settings.agent_analyst_hourly_rate,
            "minutes_per_action": settings.agent_minutes_per_action,
            "minutes_per_answer": settings.agent_minutes_per_answer,
        },
    )


def usage_payload(data: UsageReportData) -> dict:
    """JSON-serializable shape for /api/usage (the dashboard renders straight off this)."""
    return {
        "generated_at": data.generated_at.isoformat(),
        "window_days": data.window_days,
        "window_label": data.window_label,
        "totals": {
            "turns": data.turns,
            "sessions": data.sessions,
            "input_tokens": data.input_tokens,
            "output_tokens": data.output_tokens,
            "total_tokens": data.total_tokens,
            "cost_usd": round(data.cost_usd, 4),
            "cost_per_turn": round(data.cost_per_turn, 4),
            "tool_calls": data.tool_calls,
            "tool_errors": data.tool_errors,
        },
        "by_model": [
            {
                "model": m.model,
                "turns": m.turns,
                "input_tokens": m.input_tokens,
                "output_tokens": m.output_tokens,
                "total_tokens": m.total_tokens,
                "cost_usd": round(m.cost_usd, 4),
            }
            for m in data.by_model
        ],
        "by_tool": [
            {
                "name": t.name,
                "calls": t.calls,
                "errors": t.errors,
                "error_rate": round(t.error_rate, 4),
                "is_write": t.is_write,
            }
            for t in data.by_tool
        ],
        "daily": [
            {
                "day": d.day.isoformat(),
                "turns": d.turns,
                "total_tokens": d.total_tokens,
                "cost_usd": round(d.cost_usd, 4),
            }
            for d in data.daily
        ],
        "ledger_outcomes": data.ledger_outcomes,
        "value": {
            "actions_automated": data.value.actions_automated,
            "questions_answered": data.value.questions_answered,
            "analyst_hours_saved": round(data.value.analyst_hours_saved, 2),
            "labor_value_usd": round(data.value.labor_value_usd, 2),
            "agent_cost_usd": round(data.value.agent_cost_usd, 4),
            "net_value_usd": round(data.value.net_value_usd, 2),
            "roi_multiple": round(data.value.roi_multiple, 1) if data.value.roi_multiple is not None else None,
        },
        "pricing": data.pricing,
    }
