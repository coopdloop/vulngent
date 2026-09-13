from __future__ import annotations

import datetime as dt
import json

import pytest
from sqlalchemy.orm import Session

from vulngent.config import get_settings
from vulngent.db.models import ChatMessage, ChatThread, Severity
from vulngent.db import repository as repo
from vulngent.reporting import render_usage_report
from vulngent.usage_data import collect_usage_data, usage_payload


@pytest.fixture(autouse=True)
def fixed_rates(monkeypatch):
    """Pin the economics knobs so assertions don't depend on a developer's .env."""
    settings = get_settings()
    for attr, value in (
        ("agent_cost_input_per_mtok", 3.0),
        ("agent_cost_output_per_mtok", 15.0),
        ("agent_analyst_hourly_rate", 60.0),
        ("agent_minutes_per_action", 12.0),
        ("agent_minutes_per_answer", 6.0),
    ):
        monkeypatch.setattr(settings, attr, value, raising=False)
    yield


def _turn(session: Session, thread_id: str, *, in_tok: int, out_tok: int, tool_calls=(), model="anthropic/claude-sonnet-4.5", created_at=None) -> None:
    if session.get(ChatThread, thread_id) is None:
        session.add(ChatThread(id=thread_id, model=model))
    payload = {
        "role": "assistant",
        "message": "ok",
        "tool_calls": list(tool_calls),
        "usage": {"input_tokens": in_tok, "output_tokens": out_tok, "model": model},
    }
    msg = ChatMessage(thread_id=thread_id, role="assistant", payload=json.dumps(payload))
    if created_at is not None:
        msg.created_at = created_at
    session.add(msg)
    session.commit()


def test_collect_usage_aggregates_tokens_and_prices_them(session: Session) -> None:
    _turn(session, "t1", in_tok=1_000_000, out_tok=1_000_000)

    data = collect_usage_data(session)

    assert data.turns == 1
    assert data.sessions == 1
    assert data.input_tokens == 1_000_000
    assert data.output_tokens == 1_000_000
    assert data.cost_usd == pytest.approx(18.0)  # 3 + 15 per 1M
    assert data.cost_per_turn == pytest.approx(18.0)


def test_write_tool_calls_count_as_automated_actions(session: Session) -> None:
    _turn(
        session,
        "t1",
        in_tok=0,
        out_tok=0,
        tool_calls=[
            {"name": "send_slack_update", "is_error": False},
            {"name": "list_open_vulnerabilities", "is_error": False},
        ],
    )
    _turn(session, "t1", in_tok=0, out_tok=0, tool_calls=[{"name": "list_assets", "is_error": True}])

    data = collect_usage_data(session)

    assert data.tool_calls == 3
    assert data.tool_errors == 1
    assert data.value.actions_automated == 1
    # Second turn had only read tools, so it counts as an answered question.
    assert data.value.questions_answered == 1
    assert data.value.analyst_minutes_saved == pytest.approx(12.0 + 6.0)
    assert data.value.labor_value_usd == pytest.approx(18.0)


def test_errored_write_tool_is_not_counted_as_automated(session: Session) -> None:
    _turn(session, "t1", in_tok=0, out_tok=0, tool_calls=[{"name": "send_slack_update", "is_error": True}])

    data = collect_usage_data(session)

    assert data.value.actions_automated == 0
    assert data.value.questions_answered == 1


def test_roi_is_none_when_nothing_was_spent(session: Session) -> None:
    _turn(session, "t1", in_tok=0, out_tok=0)

    data = collect_usage_data(session)

    assert data.value.agent_cost_usd == 0
    assert data.value.roi_multiple is None
    assert data.value.net_value_usd > 0


def test_window_excludes_older_turns(session: Session) -> None:
    old = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=60)
    _turn(session, "old", in_tok=500, out_tok=500, created_at=old)
    _turn(session, "new", in_tok=100, out_tok=100)

    windowed = collect_usage_data(session, window_days=30)
    all_time = collect_usage_data(session, window_days=None)

    assert windowed.turns == 1
    assert windowed.input_tokens == 100
    assert all_time.turns == 2
    assert all_time.input_tokens == 600


def test_by_model_splits_costs_per_model(session: Session) -> None:
    _turn(session, "t1", in_tok=1_000_000, out_tok=0, model="anthropic/claude-sonnet-4.5")
    _turn(session, "t2", in_tok=0, out_tok=1_000_000, model="openai/gpt-4o")

    data = collect_usage_data(session)

    by_model = {m.model: m for m in data.by_model}
    assert by_model["anthropic/claude-sonnet-4.5"].cost_usd == pytest.approx(3.0)
    assert by_model["openai/gpt-4o"].cost_usd == pytest.approx(15.0)
    assert data.by_model[0].model == "openai/gpt-4o"  # sorted by cost desc


def test_ledger_outcomes_track_remediations(session: Session) -> None:
    asset = repo.get_or_create_asset(session, "svc-a")
    vuln = repo.create_vulnerability(
        session, external_id="CVE-1", title="a", severity=Severity.HIGH, asset=asset,
        discovered_at=dt.datetime.now(dt.timezone.utc),
    )
    from vulngent.db.models import VulnStatus

    repo.set_vulnerability_status(session, vuln, VulnStatus.REMEDIATED)
    session.commit()

    data = collect_usage_data(session)

    assert data.ledger_outcomes["vulns_remediated"] == 1
    assert data.ledger_outcomes["timeline_events"] >= 1


def test_usage_payload_is_json_serializable(session: Session) -> None:
    _turn(session, "t1", in_tok=10, out_tok=20, tool_calls=[{"name": "record_commitment", "is_error": False}])

    payload = usage_payload(collect_usage_data(session))
    json.dumps(payload)  # raises if anything non-serializable slipped in

    assert payload["totals"]["turns"] == 1
    assert payload["by_tool"][0]["is_write"] is True
    assert payload["value"]["actions_automated"] == 1


def test_render_usage_markdown_includes_value_section(session: Session) -> None:
    _turn(session, "t1", in_tok=1_000_000, out_tok=0, tool_calls=[{"name": "send_slack_update", "is_error": False}])

    md = render_usage_report(collect_usage_data(session), "md")

    assert "# " in md and "Agent Usage & Value" in md
    assert "## Cost vs value" in md
    assert "Actions automated: 1" in md
    assert "send_slack_update" in md


def test_render_usage_markdown_on_empty_ledger(session: Session) -> None:
    md = render_usage_report(collect_usage_data(session), "md")

    assert "No recorded agent turns in this window." in md
    assert "ROI: n/a" in md


def test_render_usage_pdf_and_docx_produce_bytes(session: Session) -> None:
    _turn(session, "t1", in_tok=1000, out_tok=500, tool_calls=[{"name": "sync_jira_ticket", "is_error": False}])
    data = collect_usage_data(session)

    pdf = render_usage_report(data, "pdf")
    docx = render_usage_report(data, "docx")

    assert isinstance(pdf, bytes) and pdf.startswith(b"%PDF")
    assert isinstance(docx, bytes) and docx.startswith(b"PK")
