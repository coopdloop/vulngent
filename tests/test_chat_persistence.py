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
