from __future__ import annotations

import datetime as dt

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import vulngent.chat.server as server
from vulngent.db.models import Base, ChatMention, ChatMessage, ChatThread, Severity, Vulnerability


@pytest.fixture()
def chat_db(monkeypatch):
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)

    from contextlib import contextmanager

    @contextmanager
    def fake_get_session():
        with factory() as s:
            yield s

    monkeypatch.setattr(server, "get_session", fake_get_session)
    # Force auth off so the HTTP endpoints under test don't require a signed-in
    # user (a real GOOGLE_CLIENT_ID in .env would otherwise enable it).
    import vulngent.chat.auth as auth_mod
    from vulngent.config import get_settings

    settings = get_settings()
    monkeypatch.setattr(type(settings), "auth_enabled", property(lambda self: False))
    monkeypatch.setattr(auth_mod, "get_session", fake_get_session)
    with factory() as s:
        s.add(
            Vulnerability(
                external_id="CVE-2099-0001",
                title="Test vuln",
                severity=Severity.CRITICAL,
                discovered_at=dt.datetime.now(dt.timezone.utc),
            )
        )
        s.commit()
    return factory


def test_persist_and_resume_roundtrip(chat_db):
    session = server.ChatSession()
    session.persist_user_message("Tell me about CVE-2099-0001")
    entry = {
        "role": "assistant",
        "message": "CVE-2099-0001 is critical.",
        "tool_summary": None,
        "tool_calls": [],
        "thoughts": [],
        "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
    }
    session.persist_assistant_entry(entry)

    with chat_db() as s:
        thread = s.get(ChatThread, session.session_id)
        assert thread is not None
        assert thread.title.startswith("Tell me about")
        messages = s.execute(select(ChatMessage).where(ChatMessage.thread_id == thread.id)).scalars().all()
        assert [m.role for m in messages] == ["user", "assistant"]
        mentions = s.execute(select(ChatMention).where(ChatMention.thread_id == thread.id)).scalars().all()
        assert len(mentions) == 1

    restored = server.ChatSession()
    entries = restored.load_thread(session.session_id)
    assert restored.session_id == session.session_id
    assert [e["role"] for e in entries] == ["user", "assistant"]
    assert len(restored.history) == 1
    assert restored._mentioned_vuln_ids == {1}


def test_load_thread_unknown_raises(chat_db):
    session = server.ChatSession()
    with pytest.raises(KeyError):
        session.load_thread("nope1234")


def test_collect_sessions_and_dashboard_chats(chat_db):
    session = server.ChatSession()
    session.persist_user_message("What is CVE-2099-0001?")

    listing = server._collect_sessions()
    assert listing["sessions"][0]["id"] == session.session_id
    assert listing["sessions"][0]["message_count"] == 1

    dashboard = server._collect_dashboard()
    top = dashboard["top_vulns"]
    assert top[0]["chats"] == [{"id": session.session_id, "title": "What is CVE-2099-0001?"}]


def test_split_sections():
    text = (
        "Intro line.\n"
        "[SECTION:summary]\nTwo criticals are overdue.\n[/SECTION]\n"
        "Middle.\n"
        "[SECTION:next_steps]\n- Patch openssl\n- Rotate keys\n[/SECTION]\n"
        "Outro."
    )
    clean, sections = server.split_sections(text)
    assert [s["key"] for s in sections] == ["summary", "next_steps"]
    assert sections[0]["content"] == "Two criticals are overdue."
    assert "Patch openssl" in sections[1]["content"]
    assert "[SECTION" not in clean
    assert "Two criticals are overdue." in clean
    assert "Intro line." in clean


def test_split_sections_no_markers():
    clean, sections = server.split_sections("Just a plain reply.")
    assert clean == "Just a plain reply."
    assert sections == []


def test_collect_sessions_filters_archived(chat_db):
    keep = server.ChatSession()
    keep.persist_user_message("keep me")
    archived = server.ChatSession()
    archived.persist_user_message("archive me")
    with chat_db() as s:
        thread = s.get(ChatThread, archived.session_id)
        thread.archived_at = dt.datetime.now(dt.timezone.utc)
        s.commit()

    active = server._collect_sessions(archived=False)
    archived_listing = server._collect_sessions(archived=True)
    assert keep.session_id in [t["id"] for t in active["sessions"]]
    assert archived.session_id not in [t["id"] for t in active["sessions"]]
    assert archived.session_id in [t["id"] for t in archived_listing["sessions"]]


def test_archive_and_delete_endpoints(chat_db):
    from fastapi.testclient import TestClient

    session = server.ChatSession()
    session.persist_user_message("to delete")

    with TestClient(server.app) as client:
        res = client.post(f"/api/sessions/{session.session_id}/archive")
        assert res.status_code == 200
        assert res.json() == {"ok": True, "archived": True}
        res = client.post(f"/api/sessions/{session.session_id}/archive?archived=false")
        assert res.json() == {"ok": True, "archived": False}

        res = client.post("/api/sessions/nope1234/archive")
        assert res.status_code == 404

        res = client.delete(f"/api/sessions/{session.session_id}")
        assert res.status_code == 200
        res = client.delete(f"/api/sessions/{session.session_id}")
        assert res.status_code == 404

    with chat_db() as s:
        assert s.get(ChatThread, session.session_id) is None
        assert s.execute(select(ChatMessage).where(ChatMessage.thread_id == session.session_id)).scalars().all() == []


def test_usage_endpoint_reflects_persisted_turns(chat_db):
    from fastapi.testclient import TestClient

    session = server.ChatSession()
    session.persist_assistant_entry(
        {
            "role": "assistant",
            "message": "done",
            "tool_calls": [{"name": "send_slack_update", "is_error": False}],
            "usage": {"input_tokens": 1000, "output_tokens": 500, "model": "anthropic/claude-sonnet-4.5"},
            "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
        }
    )

    with TestClient(server.app) as client:
        payload = client.get("/api/usage?window_days=30").json()
        assert payload["totals"]["turns"] == 1
        assert payload["totals"]["input_tokens"] == 1000
        assert payload["value"]["actions_automated"] == 1

        md = client.get("/api/reports/usage?format=md")
        assert md.status_code == 200
        assert "Agent Usage & Value" in md.text

        bad = client.get("/api/reports/usage?format=xls")
        assert bad.status_code == 400
